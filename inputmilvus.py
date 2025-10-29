import os
import gc
import time
import logging
import pandas as pd
import threading
from concurrent.futures import ThreadPoolExecutor, as_completed
from pymilvus import connections, Collection, CollectionSchema, FieldSchema, DataType, utility
from sentence_transformers import SentenceTransformer

# ======================
# 설정
# ======================
json_path = r"C:\Users\zlfnf\Desktop\q2wr423\243\view_useractivity.json"
collection_name = os.path.splitext(os.path.basename(json_path))[0]  # ex) view_system
dim = 384
BATCH_SIZE = 200
THREADS = 5

# ======================
# 로그 설정
# ======================
logging.basicConfig(
    filename="milvus_thread_log.txt",
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

if utility.has_collection(collection_name):
    utility.drop_collection(collection_name)

fields = [
    FieldSchema(name="id", dtype=DataType.INT64, is_primary=True, auto_id=False),
    FieldSchema(name="vector", dtype=DataType.FLOAT_VECTOR, dim=dim),
    FieldSchema(name="text", dtype=DataType.VARCHAR, max_length=65535),
]
schema = CollectionSchema(fields, description="Forensic artifacts (threaded insert)")
collection = Collection(name=collection_name, schema=schema)
collection.create_index(field_name="vector", index_params={"metric_type": "IP", "index_type": "HNSW", "params": {"M": 8, "efConstruction": 64}})
log("✅ Collection created")

# ======================
# 2️⃣ JSON 로드 + 텍스트 변환
# ======================
df = pd.read_json(json_path, orient="records")
df["all_columns_text"] = df.astype(str).apply(
    lambda row: " | ".join([f"{col}: {val}" for col, val in row.items()]),
    axis=1
)
texts = df["all_columns_text"].tolist()
ids = df.index.astype("int64").tolist()
log(f"📦 Loaded {len(texts)} rows")

# ======================
# 3️⃣ 임베딩 모델 로드
# ======================
model = SentenceTransformer("paraphrase-multilingual-MiniLM-L12-v2")

# ======================
# 4️⃣ 배치 단위로 분할
# ======================
batches = [(ids[i:i+BATCH_SIZE], texts[i:i+BATCH_SIZE]) for i in range(0, len(ids), BATCH_SIZE)]
log(f"🔹 Total batches: {len(batches)} (Batch size: {BATCH_SIZE})")

# ======================
# 5️⃣ 쓰레드 작업 함수
# ======================
def process_batch(batch_id, id_list, text_list):
    thread_name = threading.current_thread().name
    try:
        start = time.perf_counter()
        log(f"🟢 [START] Thread-{batch_id} ({thread_name}) → Processing {len(id_list)} items...")

        # --- 임베딩 ---
        vectors = model.encode(text_list, batch_size=32, convert_to_numpy=True, show_progress_bar=False)
        mid_time = time.perf_counter()
        log(f"   ↳ [Thread-{batch_id}] Embedding done ({mid_time - start:.2f}s)")

        # --- Milvus 삽입 ---
        collection.insert([id_list, vectors, text_list])
        collection.flush()

        elapsed = time.perf_counter() - start
        log(f"🔵 [END] Thread-{batch_id} ({thread_name}) ✅ Inserted {len(id_list)} items in {elapsed:.2f}s\n")
        gc.collect()
        return f"Thread-{batch_id} finished in {elapsed:.2f}s"
    except Exception as e:
        log(f"🔴 [ERROR] Thread-{batch_id} ({thread_name}) ❌ {e}")
        return str(e)

# ======================
# 6️⃣ 쓰레드풀 실행 + 상태 모니터링
# ======================
start_total = time.perf_counter()
log(f"🚀 Starting multi-threaded insert ({THREADS} threads)...")

with ThreadPoolExecutor(max_workers=THREADS) as executor:
    futures = {executor.submit(process_batch, i, b[0], b[1]): i for i, b in enumerate(batches)}

    active_threads = set()

    # 실시간 모니터링
    while any(future.running() for future in futures):
        current = [t.name for t in threading.enumerate() if t.name.startswith("ThreadPoolExecutor")]
        if current != active_threads:
            active_threads = set(current)
            log(f"⚙️ Currently active threads: {list(active_threads)}")
        time.sleep(1)

    # 완료된 작업 결과
    for future in as_completed(futures):
        result = future.result()
        print(result)

total_elapsed = time.perf_counter() - start_total
log(f"🏁 All threads completed. Total time: {total_elapsed:.2f}s")
log(f"✅ Final row count: {collection.num_entities}")
print(f"✅ Total inserted: {collection.num_entities}")
