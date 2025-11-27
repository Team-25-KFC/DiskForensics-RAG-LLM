# 3rd stage: map tactics/ttp back to artifact_all
# - Uses outputs from stage1 (artifact_env_ttp populated) and stage2 (tactic/ttp filled)
# - Fills SRUM and SystemInfo rows in artifact_all where tactic/ttp are still empty/Unknown

import psycopg2
from psycopg2.extras import DictCursor

DB_INFO = dict(
    dbname="forensic_db",
    user="postgres",
    password="admin123",
    host="localhost",
    port="5432",
)

# source/target tables
SRC_ENV_TABLE = "artifact_env_ttp"   # stage1/2 output (representative artifacts with tactic/ttp)
ALL_TABLE     = "artifact_all"       # main artifact table to backfill

# ----------------------------------------------------------------------
# helpers
# ----------------------------------------------------------------------

def get_conn():
    print("[+] PostgreSQL 연결 시도...")
    conn = psycopg2.connect(**DB_INFO)
    print("[+] 연결 성공")
    return conn


def extract_srum_key(text: str):
    """Extract (ExeInfo, SidType) from SRUM/UserActivity description string."""
    if not text:
        return None

    exeinfo = None
    sidtype = None
    for part in text.split("|"):
        part = part.strip()
        if part.startswith("ExeInfo :"):
            exeinfo = part[len("ExeInfo :"):].strip()
        elif part.startswith("SidType :"):
            sidtype = part[len("SidType :"):].strip()
    if exeinfo and sidtype:
        return (exeinfo, sidtype)
    return None


# ----------------------------------------------------------------------
# 1) Build SRUM mapping from artifact_env_ttp (already LLM-tagged)
# ----------------------------------------------------------------------

def build_srum_mapping(conn):
    cur = conn.cursor()
    print("[SRUM] 매핑 딕셔너리 구성 중...")

    cur.execute(
        f"""
        SELECT artifact, tactic, ttp
        FROM {SRC_ENV_TABLE}
        WHERE tactic IS NOT NULL AND tactic <> '' AND tactic <> 'Unknown'
        """
    )
    rows = cur.fetchall()
    print(f"[SRUM] {len(rows)}건 로드")

    mapping = {}
    for artifact, tactic, ttp in rows:
        key = extract_srum_key(artifact)
        if not key:
            continue
        mapping[key] = (tactic, ttp)

    print(f"[SRUM] (ExeInfo, SidType) 키 개수: {len(mapping)}")
    cur.close()
    return mapping


# ----------------------------------------------------------------------
# 2) Apply SRUM mapping to artifact_all (only empty/Unknown tactics)
# ----------------------------------------------------------------------

def apply_srum_mapping(conn, mapping):
    cur_sel = conn.cursor()
    cur_sel.execute(
        f"""
        SELECT id, description, tactic
        FROM {ALL_TABLE}
        WHERE description LIKE '%NLT_SRUM_AppResourceUseInfo%'
      """
    )
    rows = cur_sel.fetchall()
    cur_sel.close()
    print(f"[SRUM] 대상 artifact_all 행: {len(rows)}")

    cur_upd = conn.cursor()
    updated = 0
    for row_id, desc, tactic in rows:
        # skip if already set and not Unknown
        if tactic and tactic != "Unknown":
            continue
        key = extract_srum_key(desc)
        if not key:
            continue
        if key not in mapping:
            continue
        mitre_id, ttp = mapping[key]
        cur_upd.execute(
            f"""
            UPDATE {ALL_TABLE}
            SET tactic = %s, ttp = %s
            WHERE id = %s
            """,
            (mitre_id, ttp, row_id)
        )
        updated += 1
        if updated % 500 == 0:
            conn.commit()
            print(f"  - 진행: {updated}건 갱신")

    conn.commit()
    cur_upd.close()
    print(f"[SRUM] 최종 갱신 건수: {updated}")


# ----------------------------------------------------------------------
# 3) Apply SystemInfo mapping directly from artifact_env_ttp -> artifact_all
# ----------------------------------------------------------------------

def apply_systeminfo_mapping(conn):
    """
    artifact_env_ttp에 이미 채워진 SystemInfo 계열 tactic/ttp를
    artifact_all로 반영한다. (artifact_all의 tactic/ttp가 비었거나 Unknown만 대상)
    키 매칭은 src_id를 그대로 사용.
    """
    cur_src = conn.cursor(cursor_factory=DictCursor)
    cur_src.execute(
        f"""
        SELECT src_id, tactic, ttp
        FROM {SRC_ENV_TABLE}
        WHERE tactic IS NOT NULL AND tactic <> '' AND tactic <> 'Unknown'
          AND src_id IS NOT NULL
          AND (artifact LIKE '%SYS_ENV_%' OR tactic = 'SystemInfo')
        """
    )
    rows = cur_src.fetchall()
    cur_src.close()
    print(f"[SYS] artifact_env_ttp SystemInfo rows: {len(rows)}")

    cur_upd = conn.cursor()
    updated = 0
    for r in rows:
        src_id = r["src_id"]
        tactic = r["tactic"]
        ttp = r["ttp"]
        cur_upd.execute(
            f"""
            UPDATE {ALL_TABLE}
            SET tactic = %s, ttp = %s
            WHERE id = %s
              AND (tactic IS NULL OR tactic = '' OR tactic = 'Unknown')
            """,
            (tactic, ttp, src_id)
        )
        updated += cur_upd.rowcount
        if updated and updated % 500 == 0:
            conn.commit()
            print(f"  - SystemInfo 진행: {updated}건 갱신")

    conn.commit()
    cur_upd.close()
    print(f"[SYS] SystemInfo 최종 갱신 건수: {updated}")


# ----------------------------------------------------------------------
# main
# ----------------------------------------------------------------------

def main():
    conn = get_conn()
    try:
        srum_map = build_srum_mapping(conn)
        apply_srum_mapping(conn, srum_map)
        apply_systeminfo_mapping(conn)
    finally:
        conn.close()
        print("[+] 연결 종료")


if __name__ == "__main__":
    main()
