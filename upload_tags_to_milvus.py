import os
import json
import logging
from pymilvus import connections, FieldSchema, CollectionSchema, DataType, Collection, utility
from sentence_transformers import SentenceTransformer

# ======================
# 설정
# ======================
JSON_PATH = r"D:\foresic_project\tag.json"
COLLECTION_NAME = "forensic_tags_test_2"
DIM = 384  # embedding dimension for MiniLM-L12
BATCH_SIZE = 100

# ======================
# 로그 설정
# ======================
logging.basicConfig(
    filename="milvus_tag_upload.log",
    level=logging.INFO,
    format="%(asctime)s - %(levelname)s - %(message)s"
)

def log(msg):
    print(msg)
    logging.info(msg)

# ======================
# 1️⃣ Milvus 연결
# ======================
connections.connect("default", host="localhost", port="19530")
log("✅ Connected to Milvus")

if utility.has_collection(COLLECTION_NAME):
    utility.drop_collection(COLLECTION_NAME)
    log(f"🗑️ Existing collection '{COLLECTION_NAME}' dropped.")

# ======================
# 2️⃣ 스키마 정의
# ======================
fields = [
    FieldSchema(name="id", dtype=DataType.INT64, is_primary=True, auto_id=True),
    FieldSchema(name="category", dtype=DataType.VARCHAR, max_length=100),
    FieldSchema(name="subcategory", dtype=DataType.VARCHAR, max_length=150),
    FieldSchema(name="description", dtype=DataType.VARCHAR, max_length=1000),
    FieldSchema(name="keywords", dtype=DataType.VARCHAR, max_length=1000),
    FieldSchema(name="embedding", dtype=DataType.FLOAT_VECTOR, dim=DIM)
]

schema = CollectionSchema(fields, description="Forensic Tag Embeddings Collection")
collection = Collection(name=COLLECTION_NAME, schema=schema)
log(f"🆕 Created collection: {COLLECTION_NAME}")

# ======================
# 3️⃣ 임베딩 모델 로드
# ======================
model = SentenceTransformer("sentence-transformers/paraphrase-multilingual-MiniLM-L12-v2")
log("🧠 Loaded embedding model")

# ======================
# 4️⃣ JSON 로드 및 배치 업로드
# ======================
with open(JSON_PATH, "r", encoding="utf-8") as f:
    tags = json.load(f)

log(f"📄 Loaded {len(tags)} tags from JSON")

def batch(iterable, n=BATCH_SIZE):
    for i in range(0, len(iterable), n):
        yield iterable[i:i + n]

for chunk in batch(tags, BATCH_SIZE):
    categories = [item["category"] for item in chunk]
    subcategories = [item["subcategory"] for item in chunk]
    descriptions = [item["description"] for item in chunk]
    keywords = [", ".join(item["keywords"]) for item in chunk]

    texts_to_embed = [
        f"{c} - {s} : {d}. Keywords: {k}"
        for c, s, d, k in zip(categories, subcategories, descriptions, keywords)
    ]

    embeddings = model.encode(texts_to_embed, show_progress_bar=True, normalize_embeddings=True)

    data = [categories, subcategories, descriptions, keywords, embeddings]
    collection.insert(data)
    log(f"✅ Inserted {len(chunk)} records")

collection.flush()
log("💾 All data flushed to Milvus")

# ======================
# 5️⃣ 인덱스 생성
# ======================
index_params = {
    "metric_type": "COSINE",
    "index_type": "IVF_FLAT",
    "params": {"nlist": 128}
}

collection.create_index(field_name="embedding", index_params=index_params)
log("📊 Index created successfully")

collection.load()
log("🚀 Collection loaded and ready for query")
