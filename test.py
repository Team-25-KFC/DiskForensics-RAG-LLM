
import pandas as pd
from pymilvus import (
    connections, Collection, CollectionSchema, FieldSchema, DataType, utility
)
from sentence_transformers import SentenceTransformer

# ======================
# 1) Milvus 연결
# ======================
connections.connect("default", host="localhost", port="19530")

collection_name = "test_useractivity"
dim = 384  # paraphrase-multilingual-MiniLM-L12-v2 임베딩 차원

# ======================
# 2) 스키마 정의
# ======================
fields = [
    FieldSchema(name="id", dtype=DataType.INT64, is_primary=True, auto_id=False),
    FieldSchema(name="vector", dtype=DataType.FLOAT_VECTOR, dim=dim),
    FieldSchema(name="text", dtype=DataType.VARCHAR, max_length=65535),
]
schema = CollectionSchema(fields, description="Clean collection with id, vector, text")

# 기존 컬렉션 있으면 삭제 후 생성
if utility.has_collection(collection_name):
    utility.drop_collection(collection_name)

collection = Collection(name=collection_name, schema=schema)

# (선택) 인덱스 생성
index_params = {
    "metric_type": "IP",          # 또는 "L2", "COSINE"
    "index_type": "HNSW",         # IVF_FLAT/IVF_SQ8/IVF_PQ/HNSW 등
    "params": {"M": 8, "efConstruction": 64},
}
collection.create_index(field_name="vector", index_params=index_params)

# ======================
# 3) JSON 읽기
# ======================
json_path = r"C:\Users\zlfnf\Desktop\q2wr423\243\view_useractivity.json"

# orient="records" → [ {col:val, col2:val2}, {...} ] 구조를 읽기 좋음
df = pd.read_json(json_path, orient="records")

# 텍스트 필드 생성: "컬럼명: 값" 형태로 합치기
df["all_columns_text"] = df.astype(str).apply(
    lambda row: " | ".join([f"{col}: {val}" for col, val in row.items()]),
    axis=1
)

# ======================
# 4) 임베딩 모델
# ======================
model = SentenceTransformer("paraphrase-multilingual-MiniLM-L12-v2")

# ======================
# 5) 데이터 삽입
# ======================
texts = df["all_columns_text"].tolist()
vectors = model.encode(texts, convert_to_numpy=True)  # shape: (N, 384)

# PK는 Python int 리스트로
ids = df.index.astype("int64").tolist()

# 길이 안전 체크
assert len(ids) == len(vectors) == len(texts)

data_to_insert = [ids, vectors, texts]
collection.insert(data_to_insert)
collection.flush()  # 영속화

print(f"✅ {collection.num_entities} rows inserted into '{collection_name}'")