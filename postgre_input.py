import os
import json
import time
import psycopg2
from psycopg2.extras import execute_values
from concurrent.futures import ThreadPoolExecutor, as_completed


# 0️⃣ 기본 설정
BASE_DIR = r"C:\Users\aromi\바탕 화면\langflow\lang_flow\data_jsonl"
MAX_WORKERS = 4  # 병렬 업로드 스레드 수

DB_INFO = dict(
    dbname="rudrb",
    user="rudrb",
    password="rudrb123",
    host="localhost",
    port="5432"
)

# 1️⃣ PostgreSQL 연결
print(" PostgreSQL 연결 시도 중...")
conn = psycopg2.connect(**DB_INFO)
cur = conn.cursor()
print(" PostgreSQL 연결 성공")

# 1.5️ 기존 테이블 전체 삭제 (초기화 단계)
def drop_all_tables():
    try:
        cur.execute("""
            DO $$
            DECLARE
                r RECORD;
            BEGIN
                FOR r IN (SELECT tablename FROM pg_tables WHERE schemaname = 'public') LOOP
                    EXECUTE 'DROP TABLE IF EXISTS "' || r.tablename || '" CASCADE;';
                END LOOP;
            END $$;
        """)
        conn.commit()
        print("🧹 기존 모든 테이블 삭제 완료")
    except Exception as e:
        conn.rollback()
        print(f" 기존 테이블 삭제 중 오류 발생: {e}")

drop_all_tables()

# 2️ 테이블 생성 함수
def recreate_table(table_name):
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

# 3️ JSONL 파일 업로드 함수
def upload_jsonl_to_db(table_name, file_path):
    try:
        local_conn = psycopg2.connect(**DB_INFO)
        local_cur = local_conn.cursor()

        rows = []
        with open(file_path, "r", encoding="utf-8") as f:
            for line in f:
                if not line.strip():
                    continue
                record = json.loads(line.strip())
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
        return (file_path, len(rows), None)
    except Exception as e:
        return (file_path, 0, str(e))

# 4️⃣ 병렬 업로드 실행
def upload_all_jsonl():
    files = [f for f in os.listdir(BASE_DIR) if f.lower().endswith(".jsonl")]
    if not files:
        print(" 업로드할 JSONL 파일이 없습니다.")
        return

    print(f"\n 총 {len(files)}개 JSONL 파일 탐지됨")

    start_all = time.time()
    for file in files:
        table_name = os.path.splitext(file)[0]
        file_path = os.path.join(BASE_DIR, file)

        print(f"\n {table_name} 업로드 시작")
        recreate_table(table_name)

        with ThreadPoolExecutor(max_workers=MAX_WORKERS) as executor:
            futures = [executor.submit(upload_jsonl_to_db, table_name, file_path)]
            total_inserted = 0
            for future in as_completed(futures):
                file_path, inserted, error = future.result()
                if error:
                    print(f" {os.path.basename(file_path)} 오류: {error}")
                else:
                    print(f" {os.path.basename(file_path)} 완료 ({inserted}개 업로드)")
                    total_inserted += inserted
            print(f" {table_name} 총 {total_inserted}개 업로드 완료 ")

    print(f"\n 전체 DB 업로드 완료 (총 {(time.time()-start_all)/60:.2f}분 소요)")

# 5️⃣ 메인 실행
if __name__ == "__main__":
    start = time.time()
    upload_all_jsonl()
    print(f"\n전체 파이프라인 완료! 총 {(time.time()-start)/60:.2f}분 소요")

    cur.close()
    conn.close()
    print(" PostgreSQL 연결 종료 완료 ")
