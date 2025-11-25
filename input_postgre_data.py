import os
import json
import time
import psycopg2
from psycopg2.extras import execute_values
from concurrent.futures import ThreadPoolExecutor, as_completed

# 0️⃣ 기본 설정
BASE_DIR = r"D:\foresic_project\TAG_TEST_CSV\data_jsonl"
MAX_WORKERS = 4  # 병렬 업로드 스레드 수

DB_INFO = dict(
    dbname="forensic_db",   # 실제 DB 이름
    user="postgres",        # 실제 사용자 이름
    password="admin123",    # 실제 비밀번호
    host="localhost",
    port="5432"             # 포트 (기본 5432, 다르면 바꿔라)
)

# 모든 JSONL를 넣을 메인 테이블 이름
GENERAL_TABLE = "artifact_all"
# 이벤트 로그만 따로 넣을 테이블 이름
EVENT_TABLE = "eventlog_all"

print(" PostgreSQL 연결 시도 중...")
conn = psycopg2.connect(**DB_INFO)
cur = conn.cursor()
print(" PostgreSQL 연결 성공")


# 1️⃣ 테이블 생성 함수 (스키마는 동일)
def recreate_table(table_name: str):
    try:
        cur.execute(f'DROP TABLE IF EXISTS "{table_name}";')
        cur.execute(f"""
        CREATE TABLE "{table_name}" (
            id SERIAL PRIMARY KEY,
            type TEXT,
            lastwritetimestamp TEXT,
            description TEXT,
            tag TEXT
        );
        """)
        conn.commit()
        print(f" {table_name} 테이블 재생성 완료")
    except Exception as e:
        conn.rollback()
        print(f" 테이블 생성 실패 ({table_name}): {e}")


# 2️⃣ 이벤트 로그 파일 판단 함수
# 예: 20251029160156_EvtxECmd_Output__converted.jsonl
def is_eventlog_file(filename: str) -> bool:
    name = filename.lower()
    return "evtxecmd_output__converted".lower() in name


# 3️⃣ JSONL 파일 업로드 함수 (지정된 테이블에 넣기)
def upload_jsonl_to_db(table_name: str, file_path: str):
    try:
        local_conn = psycopg2.connect(**DB_INFO)
        local_cur = local_conn.cursor()

        rows = []
        with open(file_path, "r", encoding="utf-8") as f:
            for line in f:
                line = line.strip()
                if not line:
                    continue
                record = json.loads(line)
                rows.append((
                    record.get("Type", ""),
                    record.get("LastWriteTimestamp", ""),
                    record.get("description", ""),
                    record.get("tag", "")
                ))

        if rows:
            execute_values(
                local_cur,
                f'INSERT INTO "{table_name}" (type, lastwritetimestamp, description, tag) VALUES %s',
                rows,
                page_size=5000
            )
            local_conn.commit()

        local_cur.close()
        local_conn.close()
        return (table_name, file_path, len(rows), None)
    except Exception as e:
        return (table_name, file_path, 0, str(e))


# 4️⃣ 병렬 업로드 실행 (모든 파일을 두 테이블 중 하나로)
def upload_all_jsonl():
    files = [f for f in os.listdir(BASE_DIR) if f.lower().endswith(".jsonl")]
    if not files:
        print(" 업로드할 JSONL 파일이 없습니다.")
        return

    print(f"\n 총 {len(files)}개 JSONL 파일 탐지됨")

    start_all = time.time()

    # 테이블별 총 개수 카운터
    total_count = {
        GENERAL_TABLE: 0,
        EVENT_TABLE: 0
    }

    tasks = []
    with ThreadPoolExecutor(max_workers=MAX_WORKERS) as executor:
        for file in files:
            file_path = os.path.join(BASE_DIR, file)

            if is_eventlog_file(file):
                table_name = EVENT_TABLE
            else:
                table_name = GENERAL_TABLE

            print(f" {file} → {table_name} 업로드 예약")
            tasks.append(executor.submit(upload_jsonl_to_db, table_name, file_path))

        for future in as_completed(tasks):
            table_name, file_path, inserted, error = future.result()
            base = os.path.basename(file_path)
            if error:
                print(f" {base} ({table_name}) 오류: {error}")
            else:
                print(f" {base} ({table_name}) 완료 ({inserted}개 업로드)")
                total_count[table_name] += inserted

    print(f"\n {GENERAL_TABLE} 총 {total_count[GENERAL_TABLE]}개 업로드 완료")
    print(f" {EVENT_TABLE} 총 {total_count[EVENT_TABLE]}개 업로드 완료")
    print(f"\n 전체 DB 업로드 완료 (총 {(time.time() - start_all) / 60:.2f}분 소요)")


# 5️⃣ 메인 실행
if __name__ == "__main__":
    start = time.time()

    # artifact_all / eventlog_all 두 개만 재생성
    recreate_table(GENERAL_TABLE)
    recreate_table(EVENT_TABLE)

    upload_all_jsonl()
    print(f"\n전체 파이프라인 완료! 총 {(time.time() - start) / 60:.2f}분 소요")

    cur.close()
    conn.close()
    print(" PostgreSQL 연결 종료 완료 ")
