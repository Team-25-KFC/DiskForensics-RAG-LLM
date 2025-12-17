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

from fastapi import FastAPI  # ★ FastAPI 추가

# =========================
# 0. 설정
# =========================

# PostgreSQL
DB_CONFIG = {
    "host": "localhost",
    "dbname": "forensic_db",
    "user": "forensic",
    "password": "change_me_strong_pw",
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
NUM_WORKERS = 3

# 한 번에 처리할 PostgreSQL row 수
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

    if len(text) > MAX_TEXT_LEN:
        text = text[:MAX_TEXT_LEN]

    return text


# =========================
# 4. 워커 함수: id % NUM_WORKERS 기준 분할
# =========================
def worker(worker_idx, summary_list):
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
        summary_list.append(f"[{name}] PostgreSQL 연결 실패: {e}")
        return

    # Milvus 컬렉션 핸들
    try:
        coll = get_collection()
    except Exception as e:
        log("ERROR", name, f"Milvus 컬렉션 핸들 획득 실패: {e}")
        traceback.print_exc()
        conn.close()
        summary_list.append(f"[{name}] Milvus 컬렉션 핸들 획득 실패: {e}")
        return

    last_id = 0
    total_processed = 0

    try:
        while True:
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

            texts = []
            ids = []

            for r in rows:
                text = build_text(r)
                texts.append(text)
                ids.append(int(r["id"]))

            t0 = time.time()
            embeddings = model.encode(
                texts,
                batch_size=len(texts),
                convert_to_numpy=True,
                show_progress_bar=False,
            )
            t1 = time.time()

            log("INFO", name, f"임베딩 완료 ({batch_count}개, {t1 - t0:.2f}초 소요)")

            data = [
                ids,
                texts,
                embeddings.tolist(),
            ]

            try:
                insert_result = coll.insert(data)
                log(
                    "INFO",
                    name,
                    f"Milvus insert 완료 ({batch_count}개) - 예: {insert_result.primary_keys[:3]}{'...' if len(insert_result.primary_keys) > 3 else ''}",
                )
            except Exception as e:
                log("ERROR", name, f"Milvus insert 실패: {e}")
                traceback.print_exc()
                summary_list.append(f"[{name}] Milvus insert 실패: {e}")

    except Exception as e:
        log("ERROR", name, f"worker 내부 예외: {e}")
        traceback.print_exc()
        summary_list.append(f"[{name}] worker 내부 예외: {e}")
    finally:
        try:
            conn.close()
            log("INFO", name, "PostgreSQL 연결 종료")
        except Exception:
            pass

    log("INFO", name, f"종료 (총 처리 {total_processed} 행)")
    summary_list.append(f"[{name}] 총 처리 {total_processed} 행")


# =========================
# 5. 전체 파이프라인 실행 함수
# =========================
def run_milvus_embedding_pipeline():
    main_summary = []

    try:
        init_milvus()
    except Exception as e:
        msg = f"Milvus 초기화 실패: {e}"
        log("ERROR", "MAIN", msg)
        traceback.print_exc()
        return msg

    total_rows = None
    try:
        conn = psycopg2.connect(**DB_CONFIG)
        with conn.cursor(cursor_factory=DictCursor) as cur:
            cur.execute(f"SELECT COUNT(*) AS cnt FROM {RESULT_TABLE};")
            total_rows = cur.fetchone()["cnt"]
            msg = f"{RESULT_TABLE} 총 행 수: {total_rows}"
            log("INFO", "MAIN", msg)
            main_summary.append(msg)
    except Exception as e:
        msg = f"{RESULT_TABLE} 총 개수 조회 실패: {e}"
        log("ERROR", "MAIN", msg)
        traceback.print_exc()
        main_summary.append(msg)
    finally:
        try:
            conn.close()
        except Exception:
            pass

    worker_summaries = []
    threads = []
    for idx in range(NUM_WORKERS):
        t = threading.Thread(
            target=worker,
            args=(idx, worker_summaries),
            name=f"Worker-{idx}",
        )
        threads.append(t)
        t.start()
        log("INFO", "MAIN", f"Worker-{idx} 시작")

    for t in threads:
        t.join()
        log("INFO", "MAIN", f"{t.name} 종료 확인")

    log("INFO", "MAIN", "모든 워커 작업 완료")
    main_summary.append("모든 워커 작업 완료")

    try:
        coll = get_collection()
        milvus_count = coll.num_entities
        msg = f"Milvus 컬렉션 '{MILVUS_COLLECTION}' 엔티티 수: {milvus_count}"
        log("INFO", "MAIN", msg)
        main_summary.append(msg)
    except Exception as e:
        msg = f"Milvus 엔티티 수 조회 실패: {e}"
        log("ERROR", "MAIN", msg)
        traceback.print_exc()
        main_summary.append(msg)

    lines = []
    lines.append("=== Milvus Embedding Pipeline Summary ===")
    if total_rows is not None:
        lines.append(f"- {RESULT_TABLE} 총 행 수: {total_rows}")
    lines.append("")

    lines.append("=== 메인 로그 ===")
    lines.extend(main_summary)
    lines.append("")

    lines.append("=== 워커별 요약 ===")
    if worker_summaries:
        lines.extend(worker_summaries)
    else:
        lines.append("워커 요약 없음")

    return "\n".join(lines)


# =========================
# 6. FastAPI 서버 정의  ★★ 여기가 핵심
# =========================
app = FastAPI()

@app.get("/health")
def health():
    return {"status": "ok"}

@app.post("/run-embed")
def run_embed():
    summary = run_milvus_embedding_pipeline()
    return {"status": "done", "summary": summary}


if __name__ == "__main__":
    import uvicorn
    uvicorn.run(app, host="0.0.0.0", port=8001, reload=False)