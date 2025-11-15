import threading
import traceback
import time

import psycopg2
from psycopg2.extras import DictCursor

from sentence_transformers import SentenceTransformer
from pymilvus import (
    connections,
    FieldSchema,
    CollectionSchema,
    DataType,
    Collection,
    utility,
)

# =========================
# 0. 설정
# =========================

# PostgreSQL
DB_CONFIG = {
    "host": "localhost",
    "dbname": "forensic_db",
    "user": "postgres",
    "password": "admin123",
}

RESULT_TABLE = "forensic_keyword_results"

# Milvus
MILVUS_HOST = "localhost"
MILVUS_PORT = "19530"
MILVUS_COLLECTION = "tag_test"   # 👈 컬렉션 이름

# sentence-transformers 모델
ST_MODEL_NAME = "sentence-transformers/all-MiniLM-L12-v2"

# all-MiniLM-L12-v2 → 384차원
EMBED_DIM = 384

# 워커 수
NUM_WORKERS = 5

# 한 번에 처리할 PostgreSQL row 수
# 👉 더 빠르게 하고 싶으면 64 → 96, 128 등으로 올려서 테스트해봐.
BATCH_SIZE = 96

# description + type/time/tag 합친 text 4000자 제한
MAX_TEXT_LEN = 4000


# =========================
# 공통 로그 함수
# =========================
def log(level, who, msg):
    print(f"[{level}][{who}] {msg}")


# =========================
# 1. SentenceTransformer 모델 로딩 (전역 공유)
# =========================
log("INFO", "MAIN", f"임베딩 모델 로딩 중: {ST_MODEL_NAME}")
model = SentenceTransformer(ST_MODEL_NAME)
model.max_seq_length = 512  # 최대 512 토큰
log("INFO", "MAIN", "임베딩 모델 로딩 완료")


# =========================
# 2. Milvus 연결 & 컬렉션 준비
# =========================
def init_milvus():
    log("INFO", "MAIN", f"Milvus 연결 시도: {MILVUS_HOST}:{MILVUS_PORT}")
    connections.connect(
        alias="default",
        host=MILVUS_HOST,
        port=MILVUS_PORT,
    )
    log("INFO", "MAIN", "Milvus 연결 성공")

    # 기존 컬렉션 있으면 드롭
    if utility.has_collection(MILVUS_COLLECTION):
        log("INFO", "MAIN", f"기존 컬렉션 '{MILVUS_COLLECTION}' 발견 → drop_collection으로 삭제")
        utility.drop_collection(MILVUS_COLLECTION)

    # 새 스키마 정의: id, text, vector
    fields = [
        FieldSchema(
            name="id",
            dtype=DataType.INT64,
            is_primary=True,
            auto_id=False,
        ),
        FieldSchema(
            name="text",
            dtype=DataType.VARCHAR,
            max_length=MAX_TEXT_LEN,
        ),
        FieldSchema(
            name="vector",
            dtype=DataType.FLOAT_VECTOR,
            dim=EMBED_DIM,
        ),
    ]

    schema = CollectionSchema(
        fields=fields,
        description="Embeddings for forensic_keyword_results (id, text, vector)",
    )

    coll = Collection(
        name=MILVUS_COLLECTION,
        schema=schema,
        using="default",
    )

    log("INFO", "MAIN", f"컬렉션 '{MILVUS_COLLECTION}' 새로 생성 완료 (필드: id, text, vector)")

    # 인덱스 생성 (검색용)
    index_params = {
        "index_type": "IVF_FLAT",
        "metric_type": "COSINE",
        "params": {"nlist": 1024},
    }
    log("INFO", "MAIN", "벡터 인덱스 생성 중 ...")
    coll.create_index(field_name="vector", index_params=index_params)
    log("INFO", "MAIN", "벡터 인덱스 생성 완료")

    # 메모리에 로드
    coll.load()
    log("INFO", "MAIN", "컬렉션 load 완료")


def get_collection():
    return Collection(MILVUS_COLLECTION)


# =========================
# 3. 텍스트 전처리 (type / time / tag 포함)
# =========================
def build_text(row):
    """
    임베딩에 사용할 텍스트 구성:
    - type
    - lastwritetimestamp
    - tag
    - description
    전부 합쳐서 하나의 text로 만들고, 4000자 초과 시 잘라냄.
    """
    t = row.get("type") or ""
    ts = row.get("lastwritetimestamp") or ""
    tag = row.get("tag") or ""
    desc = row.get("description") or ""

    parts = []
    if t:
        parts.append(f"[type] {t}")
    if ts:
        parts.append(f"[time] {ts}")
    if tag:
        parts.append(f"[tag] {tag}")
    if desc:
        parts.append(desc)

    text = " | ".join(parts)

    # 4000자 초과 시 잘라내기 (Milvus VARCHAR max_length와 동일)
    if len(text) > MAX_TEXT_LEN:
        text = text[:MAX_TEXT_LEN]

    return text


# =========================
# 4. 워커 함수: id % NUM_WORKERS 기준 분할
# =========================
def worker(worker_idx):
    name = f"Worker-{worker_idx}"
    log("INFO", name, "시작")

    # PostgreSQL 연결
    try:
        conn = psycopg2.connect(**DB_CONFIG)
        cur = conn.cursor(cursor_factory=DictCursor)
        log("INFO", name, "PostgreSQL 연결 성공")
    except Exception as e:
        log("ERROR", name, f"PostgreSQL 연결 실패: {e}")
        traceback.print_exc()
        return

    # Milvus 컬렉션 핸들
    try:
        coll = get_collection()
    except Exception as e:
        log("ERROR", name, f"Milvus 컬렉션 핸들 획득 실패: {e}")
        traceback.print_exc()
        conn.close()
        return

    last_id = 0
    total_processed = 0

    try:
        while True:
            # 이 워커가 담당하는 id (% NUM_WORKERS == worker_idx) 중
            # last_id 이후 것만 가져오기
            cur.execute(
                f"""
                SELECT
                    id,
                    type,
                    lastwritetimestamp,
                    tag,
                    description
                FROM {RESULT_TABLE}
                WHERE id > %s
                  AND (id %% %s) = %s
                ORDER BY id
                LIMIT %s;
                """,
                (last_id, NUM_WORKERS, worker_idx, BATCH_SIZE),
            )
            rows = cur.fetchall()

            if not rows:
                log("INFO", name, f"더 이상 처리할 행 없음. 종료. (총 처리 {total_processed} 행)")
                break

            last_id = rows[-1]["id"]
            batch_count = len(rows)
            total_processed += batch_count

            log("INFO", name, f"{batch_count}개 row 조회 (last_id={last_id}, 누적={total_processed})")

            # 텍스트 전처리
            texts = []
            ids = []

            for r in rows:
                text = build_text(r)
                texts.append(text)
                ids.append(int(r["id"]))

            # 임베딩 계산
            t0 = time.time()
            embeddings = model.encode(
                texts,
                batch_size=len(texts),  # 한 번에 이 batch 전부
                convert_to_numpy=True,
                show_progress_bar=False,
            )
            t1 = time.time()

            log("INFO", name, f"임베딩 완료 ({batch_count}개, {t1 - t0:.2f}초 소요)")

            # Milvus에 전송
            # 필드 순서: id, text, vector
            data = [
                ids,
                texts,
                embeddings.tolist(),
            ]

            try:
                insert_result = coll.insert(data)
                # primary_keys는 우리가 넣은 id 그대로라 짧게만 출력
                log(
                    "INFO",
                    name,
                    f"Milvus insert 완료 ({batch_count}개) - 예: {insert_result.primary_keys[:3]}{'...' if len(insert_result.primary_keys) > 3 else ''}",
                )
            except Exception as e:
                log("ERROR", name, f"Milvus insert 실패: {e}")
                traceback.print_exc()
                # 실패해도 다음 배치 계속

    except Exception as e:
        log("ERROR", name, f"worker 내부 예외: {e}")
        traceback.print_exc()
    finally:
        try:
            conn.close()
            log("INFO", name, "PostgreSQL 연결 종료")
        except Exception:
            pass

    log("INFO", name, f"종료 (총 처리 {total_processed} 행)")


# =========================
# 5. main
# =========================
def main():
    # 1) Milvus 초기화 (컬렉션 드롭 + 재생성 + 인덱스/로드)
    init_milvus()

    # 2) forensic_keyword_results 총 개수 정보용 출력
    try:
        conn = psycopg2.connect(**DB_CONFIG)
        with conn.cursor(cursor_factory=DictCursor) as cur:
            cur.execute(f"SELECT COUNT(*) AS cnt FROM {RESULT_TABLE};")
            cnt = cur.fetchone()["cnt"]
            log("INFO", "MAIN", f"{RESULT_TABLE} 총 행 수: {cnt}")
    except Exception as e:
        log("ERROR", "MAIN", f"총 개수 조회 실패: {e}")
        traceback.print_exc()
    finally:
        try:
            conn.close()
        except Exception:
            pass

    # 3) 워커 NUM_WORKERS개 실행
    threads = []
    for idx in range(NUM_WORKERS):
        t = threading.Thread(target=worker, args=(idx,), name=f"Worker-{idx}")
        threads.append(t)
        t.start()
        log("INFO", "MAIN", f"Worker-{idx} 시작")

    # 4) 워커 종료 대기
    for t in threads:
        t.join()
        log("INFO", "MAIN", f"{t.name} 종료 확인")

    log("INFO", "MAIN", "모든 워커 작업 완료")


if __name__ == "__main__":
    main()
