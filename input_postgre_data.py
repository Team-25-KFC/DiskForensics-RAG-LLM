import os
import json
import time
import ijson
import psycopg2
from psycopg2.extras import execute_values
from concurrent.futures import ThreadPoolExecutor, as_completed

# ==========================================
# 0️⃣ 기본 설정
# ==========================================
BASE_DIR = r"D:\foresic_project\json_file"
CHUNK_DIR = os.path.join(BASE_DIR, "json_chunks")
os.makedirs(CHUNK_DIR, exist_ok=True)

CHUNK_SIZE = 200 * 1024 * 1024  # 200MB
MAX_WORKERS = 4  # 동시에 처리할 스레드 수 (CPU/디스크 성능에 맞게 조절)

DB_INFO = dict(
    dbname="forensic_db",
    user="postgres",
    password="admin123",
    host="localhost",
    port="5432"
)

# ==========================================
# 1️⃣ PostgreSQL 연결 (메인 커넥션)
# ==========================================
print("🚀 PostgreSQL 연결 시도 중...")
conn = psycopg2.connect(**DB_INFO)
cur = conn.cursor()
print("✅ PostgreSQL 연결 성공")

# ==========================================
# 2️⃣ JSON → JSONL 분할 함수
# ==========================================
def split_json_to_jsonl(input_path, output_dir):
    file_name = os.path.basename(input_path)
    base_name = os.path.splitext(file_name)[0]
    print(f"\n📂 변환 시작: {file_name}")

    output_files = []
    file_size = os.path.getsize(input_path)

    # ✅ 200MB 미만 → 단일 JSONL
    if file_size < CHUNK_SIZE:
        output_path = os.path.join(output_dir, f"{base_name}.jsonl")
        with open(input_path, "r", encoding="utf-8") as infile, open(output_path, "w", encoding="utf-8") as out:
            try:
                data = json.load(infile)
            except Exception as e:
                print(f"⚠️ {file_name} JSON 파싱 오류: {e}")
                return []

            if isinstance(data, list):
                for record in data:
                    out.write(json.dumps(record, ensure_ascii=False) + "\n")
            elif isinstance(data, dict):
                for key, val in data.items():
                    if isinstance(val, list):
                        for record in val:
                            out.write(json.dumps(record, ensure_ascii=False) + "\n")
            else:
                out.write(json.dumps(data, ensure_ascii=False) + "\n")

        output_files.append(output_path)
        print(f"✅ {file_name} → 단일 JSONL 변환 완료 ({file_size/1024/1024:.2f}MB)")
        return output_files

    # ✅ 200MB 이상 → 스트리밍 분할
    try:
        with open(input_path, "r", encoding="utf-8") as f:
            first_event = next(ijson.parse(f))
            prefix, event, value = first_event
            root_path = "item" if event == "start_array" else "records.item"
    except Exception as e:
        print(f"⚠️ {file_name} 구조 감지 실패: {e}")
        return []

    with open(input_path, "r", encoding="utf-8") as f:
        parser = ijson.items(f, root_path)
        chunk_index, current_size, total_records = 0, 0, 0
        out_path = os.path.join(output_dir, f"{base_name}_chunk_{chunk_index}.jsonl")
        out = open(out_path, "w", encoding="utf-8")

        for record in parser:
            record_str = json.dumps(record, ensure_ascii=False)
            record_size = len(record_str.encode("utf-8")) + 1
            current_size += record_size
            total_records += 1

            if current_size >= CHUNK_SIZE:
                out.close()
                output_files.append(out_path)
                print(f"✅ {os.path.basename(out_path)} 저장 완료 (~{current_size/1024/1024:.2f}MB)")
                chunk_index += 1
                out_path = os.path.join(output_dir, f"{base_name}_chunk_{chunk_index}.jsonl")
                out = open(out_path, "w", encoding="utf-8")
                current_size = 0

            out.write(record_str + "\n")

        out.close()
        output_files.append(out_path)
        print(f"✅ {os.path.basename(out_path)} (마지막 청크 저장 완료)")
        print(f"🎯 {file_name} 총 {total_records}개 레코드, {chunk_index+1}개 청크 생성")

    return output_files

# ==========================================
# 3️⃣ 테이블 생성 함수
# ==========================================
def recreate_table(table_name):
    try:
        cur.execute(f'DROP TABLE IF EXISTS "{table_name}";')
        cur.execute(f"""
        CREATE TABLE "{table_name}" (
            id SERIAL PRIMARY KEY,
            source TEXT,
            artifact_name TEXT,
            file_name TEXT,
            full_description TEXT,
            tag TEXT
        );
        """)
        conn.commit()
        print(f"🧱 {table_name} 테이블 재생성 완료")
    except Exception as e:
        conn.rollback()
        print(f"⚠️ 테이블 생성 실패 ({table_name}): {e}")

# ==========================================
# 4️⃣ 청크 파일 1개 업로드 (개별 스레드)
# ==========================================
def upload_chunk_to_db(table_name, file_path):
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
                    record.get("source"),
                    record.get("artifact_name"),
                    record.get("file_name"),
                    record.get("full_description"),
                    record.get("tag")
                ))

        if rows:
            execute_values(
                local_cur,
                f'INSERT INTO "{table_name}" (source, artifact_name, file_name, full_description, tag) VALUES %s',
                rows,
                page_size=5000
            )
            local_conn.commit()

        local_cur.close()
        local_conn.close()
        return (file_path, len(rows), None)
    except Exception as e:
        return (file_path, 0, str(e))

# ==========================================
# 5️⃣ 전체 업로드 (병렬)
# ==========================================
def upload_jsonl_parallel():
    files = [f for f in os.listdir(CHUNK_DIR) if f.lower().endswith(".jsonl")]
    if not files:
        print("❌ 업로드할 JSONL 파일이 없습니다.")
        return

    print(f"\n🔎 총 {len(files)}개 JSONL 파일 탐지됨")
    table_map = {}
    for f in files:
        base = f.split("_chunk_")[0] if "_chunk_" in f else os.path.splitext(f)[0]
        table_map.setdefault(base, []).append(f)

    start_all = time.time()
    for table_name, chunk_list in table_map.items():
        print(f"\n🚀 {table_name} 테이블 업로드 시작 ({len(chunk_list)}개 청크)")
        recreate_table(table_name)

        with ThreadPoolExecutor(max_workers=MAX_WORKERS) as executor:
            futures = [executor.submit(upload_chunk_to_db, table_name, os.path.join(CHUNK_DIR, file)) for file in chunk_list]
            total_inserted = 0
            for future in as_completed(futures):
                file_path, inserted, error = future.result()
                if error:
                    print(f"❌ {os.path.basename(file_path)} 오류: {error}")
                else:
                    print(f"✅ {os.path.basename(file_path)} 완료 ({inserted}개)")
                    total_inserted += inserted
            print(f"🎯 {table_name} 총 {total_inserted}개 업로드 완료 ✅")

    print(f"\n✅ 전체 DB 업로드 완료 (총 {(time.time()-start_all)/60:.2f}분 소요)")

# ==========================================
# 6️⃣ 메인 실행
# ==========================================
start = time.time()
json_files = [f for f in os.listdir(BASE_DIR) if f.lower().endswith(".json")]

if not json_files:
    print(f"❌ JSON 파일이 없습니다: {BASE_DIR}")
else:
    print(f"📁 처리 대상 JSON 파일: {json_files}")

    # ✅ 1단계: JSON 파일 병렬 변환
    with ThreadPoolExecutor(max_workers=MAX_WORKERS) as executor:
        future_to_file = {executor.submit(split_json_to_jsonl, os.path.join(BASE_DIR, file), CHUNK_DIR): file for file in json_files}
        for future in as_completed(future_to_file):
            file = future_to_file[future]
            try:
                result_files = future.result()
                print(f"✅ {file} 변환 완료 → {len(result_files)}개 청크 생성")
            except Exception as e:
                print(f"❌ {file} 변환 중 오류 발생: {e}")

    # ✅ 2단계: 병렬 DB 업로드
    upload_jsonl_parallel()

print(f"\n🏁 전체 파이프라인 완료! 총 {(time.time()-start)/60:.2f}분 소요")
cur.close()
conn.close()
print("🔒 PostgreSQL 연결 종료 완료 ✅")
