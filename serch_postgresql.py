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
# 2️⃣ 여러 개의 태그 정의
# ===============================
tags = [
    {
    "category": "System",
    "subcategory": "OS_Info",
    "description": "운영체제 버전, 빌드 번호, 설치일 등 시스템 기본 환경 정보를 확인한다.",
    "keywords": ["SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion", "ProductName", "CurrentBuildNumber", "InstallDate", "RegisteredOwner"]
  }


]

# ===============================
# 3️⃣ DB 연결
# ===============================
conn = psycopg2.connect(**DB_CONFIG)
cur = conn.cursor()
# ===============================
# 4️⃣ forensic 테이블 조회 (전체)
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
total_hits = 0

# ===============================
# 5️⃣ 각 태그별로 검색 수행
# ===============================
for tag in tags:
    print(f"\n🔎 Searching for tag: {tag['subcategory']} ({tag['category']})")

    for table_name in tables:
        print(f"   └ Table: {table_name}")
        cur.execute("""
            SELECT column_name
            FROM information_schema.columns
            WHERE table_schema='public' AND table_name=%s;
        """, (table_name,))
        columns = [c[0] for c in cur.fetchall()]
        has_event_col = "event_id" in columns

        hit_count = 0
        # (여기 이후는 기존 검색 로직 그대로 유지)

        # -------------------------------
        # -------------------------------
        # (1) 키워드 검색 (exclude 조건 적용)
        # -------------------------------
        for kw in tag["keywords"]:
            exclude_conditions = " AND ".join(
                [f"full_description NOT ILIKE '%%{ex}%%'" for ex in tag.get("exclude_patterns", [])]
            )

            # ✅ "AND" 포함 키워드 처리
            if "AND" in kw:
                parts = [p.strip() for p in kw.split("AND") if p.strip()]
                conditions = " AND ".join(
                    [f"(full_description ILIKE '%{p}%' OR artifact_name ILIKE '%{p}%' OR file_name ILIKE '%{p}%')" for p in parts]
                )
                query_kw = f"""
                    SELECT *
                    FROM {table_name}
                    WHERE {conditions}
                    {f'AND {exclude_conditions}' if exclude_conditions else ''};
                """
                cur.execute(query_kw)
            else:
                # 기존 단일 키워드 로직
                query_kw = f"""
                    SELECT *
                    FROM {table_name}
                    WHERE (
                        full_description ILIKE %s
                        OR artifact_name ILIKE %s
                        OR file_name ILIKE %s
                    )
                    {f'AND {exclude_conditions}' if exclude_conditions else ''};
                """
                cur.execute(query_kw, [f"%{kw}%", f"%{kw}%", f"%{kw}%"])

            rows = cur.fetchall()
            if rows:
                count = len(rows)
                hit_count += count
                total_hits += count
                print(f"      ✅ {count} match(es) for keyword: '{kw}'")
                matched_rows.extend([(table_name, tag, "keyword", kw, r) for r in rows])


        # -------------------------------
        # (2) event_id 검색
        # -------------------------------
        for eid in tag.get("event_id", []):
            try:
                if has_event_col:
                    query_eid = f"SELECT * FROM {table_name} WHERE CAST(event_id AS TEXT) ILIKE %s;"
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
                    print(f"      ✅ {count} match(es) for Event ID: {eid}")
                    matched_rows.extend([(table_name, tag, "event_id", str(eid), r) for r in rows])

            except psycopg2.errors.UndefinedColumn:
                conn.rollback()
                continue

        summary[table_name] = summary.get(table_name, 0) + hit_count

# ===============================
# 6️⃣ 결과 요약 출력
# ===============================
print("\n=== 📊 Summary of Matches ===")
for table, count in summary.items():
    print(f"{table:<25} → {count} hit(s)")

print(f"\n🔹 Total matches across all tags: {total_hits}")

# ===============================
# 7️⃣ PostgreSQL 연결 종료
# ===============================
cur.close()
conn.close()

# ===============================
# 8️⃣ Milvus 설정
# ===============================
COLLECTION_NAME = "tag_test"
DIM = 384
MODEL_NAME = "sentence-transformers/paraphrase-multilingual-MiniLM-L12-v2"

print("\n🚀 Connecting to Milvus...")
connections.connect("default", host="localhost", port="19530")

if utility.has_collection(COLLECTION_NAME):
    utility.drop_collection(COLLECTION_NAME)
    print(f"🧹 Old collection '{COLLECTION_NAME}' dropped.")

fields = [
    FieldSchema(name="id", dtype=DataType.INT64, is_primary=True, auto_id=True),
    FieldSchema(name="text", dtype=DataType.VARCHAR, max_length=2000),
    FieldSchema(name="vector", dtype=DataType.FLOAT_VECTOR, dim=DIM),
]
schema = CollectionSchema(fields, description="Forensic filtered search results")
collection = Collection(COLLECTION_NAME, schema)
print(f"✅ Created collection: {COLLECTION_NAME}")
# ===============================
# 9️⃣ SentenceTransformer 임베딩
# ===============================
print(f"\n🔄 Loading model: {MODEL_NAME}")
model = SentenceTransformer(MODEL_NAME)

texts = []
for table, tag, match_type, value, row in matched_rows:
    content = f"[{tag['category']}/{tag['subcategory']}] ({match_type}: {value}) " \
              + " ".join(str(c) for c in row if c)
    texts.append(content[:1900])

if texts:
    print(f"\n📤 Encoding and inserting {len(texts)} rows into Milvus ...")
    embeddings = model.encode(texts, convert_to_numpy=True, show_progress_bar=True)


    BATCH_SIZE = 150  
    total = len(texts)
    total_batches = (total + BATCH_SIZE - 1) // BATCH_SIZE

    for i in range(0, total, BATCH_SIZE):
        batch_texts = texts[i:i + BATCH_SIZE]
        batch_embeds = embeddings[i:i + BATCH_SIZE].tolist()
        print(f"🚀 Inserting batch {i // BATCH_SIZE + 1}/{total_batches} ({len(batch_texts)} rows)")
        collection.insert([batch_texts, batch_embeds])

    collection.flush()
    print("✅ All batches successfully inserted into Milvus!")
else:
    print("\n⚠️ No matched rows to insert into Milvus.")

print("\n🏁 Done.")
