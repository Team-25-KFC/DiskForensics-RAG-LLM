# milvus.py
# Milvus와 상호작용하는 기능들을 포함한 모듈
import pandas as pd
from pymilvus import Collection, FieldSchema, CollectionSchema, DataType, connections, utility, MilvusClient
from sentence_transformers import SentenceTransformer
import time
import math
from config import MILVUS_HOST, MILVUS_PORT, COLLECTION_NAME, EMBEDDING_MODEL_NAME, VECTORS_DIM, CSV_FILE_PATH

def connect_to_milvus():
    try:
        connections.connect(host=MILVUS_HOST, port=MILVUS_PORT)
        return True
    except Exception as e:
        print(f"❌ Milvus 서버 연결 실패: {e}")
        return False

def setup_collection():
    if not connect_to_milvus():
        exit()

    if utility.has_collection(COLLECTION_NAME):
        print(f"✅ 기존 컬렉션 '{COLLECTION_NAME}'이(가) 존재합니다. 삭제 후 재생성합니다.")
        utility.drop_collection(COLLECTION_NAME)

    fields = [
        FieldSchema(name="pk", dtype=DataType.INT64, is_primary=True, auto_id=False),
        FieldSchema(name="embeddings", dtype=DataType.FLOAT_VECTOR, dim=VECTORS_DIM),
    ]
    schema = CollectionSchema(fields, "KFC collection for LLM RAG", enable_dynamic_field=True)

    collection = Collection(COLLECTION_NAME, schema)
    print(f"✅ 컬렉션 '{COLLECTION_NAME}'이(가) 성공적으로 생성되었습니다.")

    index_params = {
        "index_type": "IVF_FLAT",
        "metric_type": "COSINE",
        "params": {"nlist": 128},
    }
    collection.create_index("embeddings", index_params=index_params)
    print(f"✅ 인덱스 'embeddings'가 성공적으로 생성되었습니다.")
    return collection

def insert_data(collection, file_path):
    print("✅ 임베딩 모델을 로드 중입니다...")
    model = SentenceTransformer(EMBEDDING_MODEL_NAME)
    print("✅ 임베딩 모델 로드 완료.")

    try:
        df = pd.read_csv(file_path, low_memory=False)
        df.columns = df.columns.str.strip()
        print(f"✅ 파일이 성공적으로 로드되었습니다. 총 데이터 수: {len(df)}")
    except FileNotFoundError:
        print(f"❌ 파일을 찾을 수 없습니다: {file_path}")
        exit()

    df['EventRecordID'] = pd.to_numeric(df['EventRecordID'], errors='coerce')
    df['EventRecordID'] = df['EventRecordID'].fillna(0).astype(int)
    df = df.fillna("")

    start_time = time.time()
    batch_size = 1000
    total_inserted_count = 0
    errors = 0
    
    for start_index in range(0, len(df), batch_size):
        end_index = min(start_index + batch_size, len(df))
        batch_df = df.iloc[start_index:end_index]
        
        data_to_insert = []
        for _, row in batch_df.iterrows():
            try:
                text_to_embed = " | ".join([f"{col}: {val}" for col, val in row.items() if val != ""])
                vector = model.encode(text_to_embed).tolist()
                
                data_dict = {
                    "pk": int(row['EventRecordID']),
                    "embeddings": vector,
                    **row.to_dict()
                }
                data_to_insert.append(data_dict)
            except (KeyError, ValueError, TypeError) as e:
                print(f"❌ 데이터 변환 오류: 행 {start_index + _} - {e}")
                errors += 1
                continue
        
        if data_to_insert:
            try:
                collection.insert(data_to_insert)
                total_inserted_count += len(data_to_insert)
                print(f"✅ 배치 삽입 완료: {total_inserted_count} / {len(df)}")
            except Exception as e:
                print(f"❌ 데이터 삽입 오류: {e}")
                errors += len(data_to_insert)
    
    end_time = time.time()
    print(f"\n✅ 총 {total_inserted_count}개의 데이터가 삽입되었습니다.")
    print(f"❌ 오류 발생 수: {errors}")
    print(f"⏰ 총 소요 시간: {end_time - start_time:.2f}초")
    collection.flush()
    collection.load()

def search_data(query_text, limit=5):
    if not connections.has_connection("default"):
        if not connect_to_milvus():
            return []

    model = SentenceTransformer(EMBEDDING_MODEL_NAME)
    collection = Collection(COLLECTION_NAME)

    query_vector = model.encode(query_text).tolist()
    
    search_params = {
        "metric_type": "COSINE",
        "params": {"nprobe": 10},
    }

    search_result = collection.search(
        data=[query_vector],
        anns_field="embeddings",
        param=search_params,
        limit=limit,
        output_fields=["*"]
    )

    retrieved_docs = [result.entity.to_dict() for result in search_result[0]]
    return retrieved_docs

def format_docs_for_llm(docs, essential_fields):
    formatted_docs = []
    
    for doc in docs:
        formatted_str = ""
        for key in essential_fields:
            value = doc.get(key)
            if value is not None and value != "":
                formatted_str += f"{key}: {value} | "
        formatted_docs.append(formatted_str.strip(' | '))
    return "\n".join(formatted_docs)

# 이 파일을 직접 실행할 경우 데이터 업로드
if __name__ == "__main__":
    milvus_collection = setup_collection()
    insert_data(milvus_collection, CSV_FILE_PATH)