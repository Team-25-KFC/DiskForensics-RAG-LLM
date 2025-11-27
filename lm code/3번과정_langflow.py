# file: map_ttp_to_artifact_all.py

import psycopg2

DB_INFO = dict(
    dbname="forensic_db",
    user="postgres",
    password="admin123",
    host="localhost",
    port="5432",
)

# ------------------------------------------------
# 0. 공통: SRUM에서 쓰는 키(ExeInfo + SidType) 추출 함수
# ------------------------------------------------
def extract_srum_key(text: str):
    """
    artifact_srum_ttp.artifact / artifact_all.description 에 공통적으로 들어있는
    'ExeInfo :' / 'SidType :' 정보를 뽑아서 (exeinfo, sidtype) 튜플로 리턴.
    없으면 None.
    """
    exeinfo = None
    sidtype = None

    if not text:
        return None

    for part in text.split("|"):
        part = part.strip()
        if part.startswith("ExeInfo :"):
            exeinfo = part[len("ExeInfo :"):].strip()
        elif part.startswith("SidType :"):
            sidtype = part[len("SidType :"):].strip()

    if exeinfo and sidtype:
        return (exeinfo, sidtype)
    return None


# ------------------------------------------------
# 1. SRUM 대표 테이블 → (ExeInfo, SidType) → (mitre_id, ttp) 매핑 딕셔너리 생성
# ------------------------------------------------
def build_srum_mapping(conn):
    cur = conn.cursor()
    print("[SRUM] 매핑 딕셔너리 생성 시작...")

    # ⬇⬇⬇ 여기를 mitre_id → tactic 으로 수정
    cur.execute("""
        SELECT artifact, tactic, ttp
        FROM artifact_srum_ttp
        WHERE tactic IS NOT NULL AND tactic <> ''
    """)
    rows = cur.fetchall()
    print(f"[SRUM] artifact_srum_ttp에서 {len(rows)}개 행 로드")

    mapping = {}

    for artifact, tactic, ttp in rows:
        exeinfo = None
        sidtype = ""

        parts = [p.strip() for p in artifact.split("|")]
        for p in parts:
            if p.startswith("ExeInfo :"):
                exeinfo = p.split("ExeInfo :", 1)[1].strip()
            elif p.startswith("SidType :"):
                sidtype = p.split("SidType :", 1)[1].strip()

        if not exeinfo:
            continue

        key = (exeinfo, sidtype)
        mapping[key] = (tactic, ttp)

    cur.close()
    print(f"[SRUM] (ExeInfo, SidType) 기준 서로 다른 키 개수: {len(mapping)}")
    return mapping



# ------------------------------------------------
# 2. artifact_all 안에서 SRUM 레코드를 찾아서 tactic/ttp 채우기
# ------------------------------------------------
def apply_srum_mapping_to_artifact_all(conn, mapping):
    """
    artifact_all에서 SRUM 기록( NLT_SRUM_AppResourceUseInfo )만 골라서
    (ExeInfo, SidType) → mapping 딕셔너리를 이용해 tactic/ttp 업데이트.
    """
    cur_sel = conn.cursor()
    cur_sel.execute("""
        SELECT id, description
        FROM artifact_all
        WHERE description LIKE '%NLT_SRUM_AppResourceUseInfo%'
    """)
    rows = cur_sel.fetchall()
    print(f"[SRUM] artifact_all 내 SRUM 후보 행 수: {len(rows)}")

    cur_upd = conn.cursor()
    updated = 0

    for idx, (row_id, desc) in enumerate(rows, start=1):
        key = extract_srum_key(desc)
        if not key:
            continue

        if key not in mapping:
            continue

        mitre_id, ttp = mapping[key]

        cur_upd.execute("""
            UPDATE artifact_all
            SET tactic = %s,
                ttp    = %s
            WHERE id = %s
        """, (mitre_id, ttp, row_id))
        updated += 1

        # 진행 상황 로그
        if updated % 500 == 0:
            conn.commit()
            print(f"  - 현재까지 {updated}개 행 SRUM 매핑 완료...")

    conn.commit()
    print(f"[SRUM] 최종 업데이트된 행 수: {updated}")


# ------------------------------------------------
# 3. 확장 포인트: 다른 아티팩트 타입용 골격
# ------------------------------------------------
def map_other_artifact_example(conn):
    """
    예시용 함수.
    - 나중에 Prefetch, Shimcache, Amcache, EventLog 등
      다른 아티팩트에 대한 별도 매핑을 넣고 싶을 때 이 틀을 복사해서 사용.

    1) 전용 매핑 테이블에서 artifact/mitre_id/ttp 가져옴
    2) 해당 아티팩트 패턴을 가진 artifact_all 행만 SELECT
    3) 고유 키를 추출해서 UPDATE
    """
    # 1. 예시: artifact_prefetch_ttp 테이블에서 매핑 가져오기
    # (스키마는 artifact_srum_ttp와 비슷하다고 가정)
    cur = conn.cursor()
    cur.execute("""
        SELECT artifact, mitre_id, ttp
        FROM artifact_prefetch_ttp
        WHERE mitre_id IS NOT NULL AND mitre_id <> ''
    """)
    rows = cur.fetchall()

    # TODO: Prefetch에서 쓸 고유 키 추출 함수는
    #       예를 들면 (ImageName, RunCount) 같은 걸로 새로 정의해야 함.
    #       여기서는 그냥 예시로 artifact 전체 문자열을 key로 둔다고 가정.
    mapping = {}
    for artifact, mitre_id, ttp in rows:
        key = artifact.strip()
        if key:
            mapping[key] = (mitre_id, ttp)

    print(f"[PREFETCH] 매핑 키 개수: {len(mapping)}")

    # 2. artifact_all에서 Prefetch 관련 행 찾기 (예: type에 'Prefetch'가 들어가는 경우)
    cur_sel = conn.cursor()
    cur_sel.execute("""
        SELECT id, description
        FROM artifact_all
        WHERE type ILIKE '%prefetch%'
    """)
    target_rows = cur_sel.fetchall()
    print(f"[PREFETCH] artifact_all 내 Prefetch 후보 행 수: {len(target_rows)}")

    # 3. 매핑 적용 (예시: description 전체를 key로 사용)
    cur_upd = conn.cursor()
    updated = 0

    for row_id, desc in target_rows:
        key = desc.strip()
        if key not in mapping:
            continue

        mitre_id, ttp = mapping[key]
        cur_upd.execute("""
            UPDATE artifact_all
            SET tactic = %s,
                ttp    = %s
            WHERE id = %s
        """, (mitre_id, ttp, row_id))
        updated += 1

    conn.commit()
    print(f"[PREFETCH] 최종 업데이트된 행 수: {updated}")


# ------------------------------------------------
# 4. main: 여기서 여러 아티팩트별 매핑 함수를 순서대로 돌림
# ------------------------------------------------
def main():
    print("[+] PostgreSQL 연결 중...")
    conn = psycopg2.connect(**DB_INFO)
    print("[+] 연결 성공\n")

    # 1) SRUM 매핑
    srum_mapping = build_srum_mapping(conn)
    apply_srum_mapping_to_artifact_all(conn, srum_mapping)

    # 2) 다른 아티팩트 매핑 (필요할 때 켜기)
    # map_other_artifact_example(conn)

    conn.close()
    print("\n[+] 전체 매핑 작업 종료")


if __name__ == "__main__":
    main()
