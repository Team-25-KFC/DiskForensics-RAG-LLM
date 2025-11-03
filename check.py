from pymilvus import connections, Collection

connections.connect("default", host="localhost", port="19530")

collection_name = "tag_test"
collection = Collection(collection_name)

print(f"📦 현재 '{collection_name}' 컬렉션에는 {collection.num_entities}개의 엔티티가 있습니다.")
