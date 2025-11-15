from pymilvus import connections, Collection

COLLECTION_NAME = "tag_test"


def main():
    # 1) Milvus 연결
    connections.connect("default", host="localhost", port="19530")
    coll = Collection(COLLECTION_NAME)

    # 2) 컬렉션 로드
    coll.load()
    print(f"현재 '{COLLECTION_NAME}' 컬렉션에는 {coll.num_entities}개의 엔티티가 있습니다.")

    # 3) 일단 최대 1000개 정도 뽑아서 그 안에서 id 기준으로 정렬
    limit = 1000
    results = coll.query(
        expr="id >= 0",              # 전체 중 아무거나
        output_fields=["id", "text"],
        limit=limit,
    )

    if not results:
        print("query 결과가 없습니다.")
        return

    # id 내림차순으로 정렬해서 "끝부분" 쪽을 보자
    results_sorted = sorted(results, key=lambda r: r["id"], reverse=True)

    tail_n = 40
    tail = results_sorted[:tail_n]

    print(f"\n=== 끝부분 데이터 미리보기 (id 큰 순 상위 {len(tail)}개) ===")
    for idx, r in enumerate(tail, 1):
        text = (r.get("text") or "").replace("\n", " ")
        if len(text) > 300:
            text_preview = text[:300] + "..."
        else:
            text_preview = text

        print(f"{idx}. id: {r['id']}")
        print(f"   text: {text_preview}")
        print("-" * 80)


if __name__ == "__main__":
    main()
