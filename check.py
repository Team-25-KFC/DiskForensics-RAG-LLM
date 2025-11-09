from pymilvus import connections, Collection, utility

# ✅ 1️⃣ Milvus 연결
connections.connect("default", host="localhost", port="19530")

# ✅ 2️⃣ 컬렉션 선택
collection_name = "tag_test"
collection = Collection(collection_name)

# ✅ 3️⃣ 인덱스 생성 (없으면 새로)
try:
    # vector 필드에 인덱스 생성
    collection.create_index(
        field_name="vector",
        index_params={
            "index_type": "IVF_FLAT",   # 검색 효율 높이기 위한 인덱스 유형
            "metric_type": "COSINE",
            "params": {"nlist": 1024}
        }
    )
    print("✅ 벡터 인덱스 생성 완료!")
except Exception as e:
    print(f"⚠️ 인덱스 생성 중 예외 발생 (이미 존재할 수도 있음): {e}")

# ✅ 4️⃣ 컬렉션 로드
collection.load()
print("✅ 컬렉션 메모리 로드 완료!")

# ✅ 5️⃣ 데이터 조회
limit = 40
results = collection.query(expr="id >= 0", output_fields=["id", "text"], limit=limit)

# ✅ 6️⃣ 결과 출력
print(f"📦 현재 '{collection_name}' 컬렉션에는 {collection.num_entities}개의 엔티티가 있습니다.\n")
print("=== 📄 저장된 데이터 미리보기 ===")
for idx, r in enumerate(results, 1):
    text_preview = r["text"][:500].replace("\n", " ")
    print(f"{idx}. id: {r['id']}")
    print(f"   text: {text_preview}")
    print("-" * 80)
