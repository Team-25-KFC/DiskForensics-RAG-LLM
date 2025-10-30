import psycopg2
from pymilvus import connections, Collection, FieldSchema, CollectionSchema, DataType, utility
from sentence_transformers import SentenceTransformer
# ===============================
# 1️⃣ DB 설정
# ===============================
DB_CONFIG = {
    "host": "localhost",
    "dbname": "forensic_db",
    "user": "postgres",
    "password": "admin123",  # 실제 비밀번호 입력
}

# ===============================
# 2️⃣ 태그 (RAG 결과)
# ===============================
tag = {
    "category": "Persistence",
    "subcategory": "Service_Install",
    "description": "서비스 등록을 통한 지속성 확보 여부를 탐지한다.",
    "keywords": [
      "Service Control Manager",
      "CreateService",
      "sc.exe",
      "svchost.exe"
    ],
    "event_id": [7045]
  }

# ===============================
# 3️⃣ DB 연결
# ===============================
conn = psycopg2.connect(**DB_CONFIG)
cur = conn.cursor()

# ===============================
# 4️⃣ 모든 forensic 테이블 조회
# ===============================
cur.execute("""
    SELECT table_name
    FROM information_schema.tables
    WHERE table_schema='public'
      AND table_name LIKE 'view_%'
    ORDER BY table_name;
""")
tables = [t[0] for t in cur.fetchall()]
print(f"📋 Found {len(tables)} tables:", ", ".join(tables))

matched_rows = []
summary = {}
total_hits = 0  # 전체 일치 개수

# ===============================
# 5️⃣ 각 테이블에서 keyword + event_id 검색
# ===============================
for table_name in tables:
    print(f"\n🔍 Searching in table: {table_name}")

    # (1) 컬럼 목록 확인
    cur.execute("""
        SELECT column_name
        FROM information_schema.columns
        WHERE table_schema='public' AND table_name=%s;
    """, (table_name,))
    columns = [c[0] for c in cur.fetchall()]
    has_event_col = "event_id" in columns

    hit_count = 0  # 테이블별 총 매칭 개수

    # (2) 키워드 검색
    for kw in tag["keywords"]:
        query_kw = f"""
            SELECT *
            FROM {table_name}
            WHERE (full_description ILIKE %s
               OR artifact_name ILIKE %s
               OR file_name ILIKE %s);
        """
        cur.execute(query_kw, [f"%{kw}%", f"%{kw}%", f"%{kw}%"])
        rows = cur.fetchall()
        if rows:
            count = len(rows)
            hit_count += count
            total_hits += count
            print(f"✅ {count} match(es) for keyword: '{kw}'")
            matched_rows.extend([(table_name, "keyword", kw, r) for r in rows])

    # (3) event_id 검색 (컬럼이 없을 경우 문자열 검색)
    for eid in tag.get("event_id", []):
        try:
            if has_event_col:
                query_eid = f"""
                    SELECT *
                    FROM {table_name}
                    WHERE CAST(event_id AS TEXT) ILIKE %s;
                """
                cur.execute(query_eid, [f"%{eid}%"])
            else:
                query_eid = f"""
                    SELECT *
                    FROM {table_name}
                    WHERE (
                        full_description ILIKE %s
                        OR artifact_name ILIKE %s
                        OR file_name ILIKE %s
                    );
                """
                cur.execute(query_eid, [f"%{eid}%", f"%{eid}%", f"%{eid}%"])
            rows = cur.fetchall()
            if rows:
                count = len(rows)
                hit_count += count
                total_hits += count
                print(f"✅ {count} match(es) for Event ID: {eid}")
                matched_rows.extend([(table_name, "event_id", str(eid), r) for r in rows])
        except psycopg2.errors.UndefinedColumn:
            conn.rollback()
            continue

    # (4) 요약 저장
    summary[table_name] = hit_count

# ===============================
# 6️⃣ 요약 출력
# ===============================
print("\n=== 📊 Summary of Matches ===")
for table, count in summary.items():
    print(f"{table:<25} → {count} hit(s)")

# ===============================
# 7️⃣ 전체 결과 요약
# ===============================
total_tables = len(tables)
if total_hits > 0:
    print(f"\n✅ 총 {total_tables}개 테이블을 탐색한 결과, {total_hits}개의 일치 항목을 발견했습니다.")
else:
    print(f"\n❌ 총 {total_tables}개 테이블을 탐색했지만, 일치하는 항목을 찾지 못했습니다.")

# ===============================
# 8️⃣ 세부 결과 출력
# ===============================
if matched_rows:
    print("\n=== 🎯 Detailed Matched Rows ===")
    for table, match_type, value, row in matched_rows:
        print(f"[{table}] {match_type}='{value}' → {row}")

# ===============================
# 9️⃣ 종료
# ===============================
cur.close()
conn.close()
# ===============================
# 🔹 Milvus 설정
# ===============================
COLLECTION_NAME = "tag_test"
DIM = 384
MODEL_NAME = "sentence-transformers/paraphrase-multilingual-MiniLM-L12-v2"


print("\n🚀 Connecting to Milvus...")
connections.connect("default", host="localhost", port="19530")

# 기존 컬렉션 있으면 삭제 후 재생성 (원하면 유지하도록 변경 가능)
if utility.has_collection(COLLECTION_NAME):
    utility.drop_collection(COLLECTION_NAME)
    print(f"🧹 Old collection '{COLLECTION_NAME}' dropped.")

# 컬렉션 생성 (id, vector, text만)
fields = [
    FieldSchema(name="id", dtype=DataType.INT64, is_primary=True, auto_id=True),
    FieldSchema(name="text", dtype=DataType.VARCHAR, max_length=2000),
    FieldSchema(name="vector", dtype=DataType.FLOAT_VECTOR, dim=DIM),
]
schema = CollectionSchema(fields, description="Forensic filtered search results")
collection = Collection(COLLECTION_NAME, schema)
print(f"✅ Created collection: {COLLECTION_NAME}")

# ===============================
# 🔹 SentenceTransformer 임베딩
# ===============================
print(f"\n🔄 Loading model: {MODEL_NAME}")
model = SentenceTransformer(MODEL_NAME)

# PostgreSQL 검색 결과에서 텍스트 생성
texts = []
for table, match_type, value, row in matched_rows:
    # 태그 정보 + 매칭 정보 + 전체 행 내용 전부 하나의 문자열로 합침
    content = f"[{tag['category']}/{tag['subcategory']}] ({match_type}: {value}) " \
              + " ".join(str(c) for c in row if c)
    texts.append(content[:1900])  # 길이 제한

if not texts:
    print("\n⚠️ No matched rows to insert into Milvus.")
else:
    embeddings = model.encode(texts, convert_to_numpy=True, show_progress_bar=True)

   # ===============================
# 🔹 Milvus 업로드
# ===============================
print(f"\n📤 Inserting {len(texts)} rows into Milvus ({COLLECTION_NAME}) ...")

# ✅ id는 auto_id=True 이므로 제거
collection.insert([
    texts,                   # text
    embeddings.tolist(),      # vector
])

collection.flush()
print("✅ Data successfully inserted into Milvus!")
print("\n🏁 Done.")