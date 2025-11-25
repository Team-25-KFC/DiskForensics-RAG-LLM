# -*- coding: utf-8 -*-
"""
artifact_all 테이블에서 SRUM(AppResourceUseInfo) / UserActivity 관련 아티팩트를 가져와서
실행 파일 이름(ExeBase) + 권한 컨텍스트(SidType) 기준으로 "대표"만 고르고,
그 대표들을 artifact_srum_ttp 테이블에 넣는 스크립트.

⚠ artifact_srum_ttp 테이블 스키마는 공용으로 쓰기 위해
   id, src_id, artifact, tactic, ttp 만 가진다.
   tactic / ttp 는 지금 단계에서는 전부 NULL로 넣고,
   나중에 LLM이 이 테이블을 보고 태그를 채울 예정이다.
"""

import psycopg2
from psycopg2.extras import DictCursor

# =====================
# 0. 공용 설정
# =====================

DB_INFO = dict(
    dbname="forensic_db",
    user="postgres",
    password="admin123",
    host="localhost",
    port="5432",
)

GENERAL_TABLE = "artifact_all"       # 전체 아티팩트 메인 테이블
TARGET_TABLE = "artifact_srum_ttp"   # SRUM 대표 패턴 + LLM 태깅용 테이블


# =====================
# 1. 공용 유틸 함수
# =====================

def get_connection():
    """PostgreSQL 커넥션 생성."""
    print("[+] PostgreSQL 연결 중...")
    conn = psycopg2.connect(**DB_INFO)
    print("[+] 연결 성공")
    return conn


def normalize_exeinfo(exeinfo: str) -> str:
    """
    ExeInfo에서 실행 파일/앱 이름(ExeBase)만 추출.
    예) '\\Device\\HarddiskVolume3\\Windows\\System32\\conhost.exe' -> 'conhost.exe'
        'svchost.exe [utcsvc]' -> 'svchost.exe'
    """
    if not isinstance(exeinfo, str):
        exeinfo = str(exeinfo)

    exeinfo = exeinfo.strip()
    if not exeinfo:
        return "(EMPTY)"

    exeinfo = exeinfo.replace("\\", "/")
    base = exeinfo.rsplit("/", 1)[-1]

    # 'svchost.exe [utcsvc]' → 'svchost.exe'
    if " " in base:
        base = base.split(" ", 1)[0]

    return base or "(EMPTY)"


def parse_description_to_dict(desc: str) -> dict:
    """
    SRUM / UserActivity description 문자열을
    'Key : Value | Key2 : Value2 | ...' 형태로 보고 dict로 변환.

    예)
    'type : NLT_SRUM_AppResourceUseInfo | description : Id : 439595 | ExeInfo : ... | SidType : LocalSystem | UserName : ...'
    """
    if not isinstance(desc, str):
        desc = str(desc)

    result = {}
    parts = desc.split(" | ")
    for part in parts:
        if " : " in part:
            key, value = part.split(" : ", 1)  # 첫 번째 ' : '만 기준으로 나눔
            key = key.strip()
            value = value.strip()
            if key:
                result[key] = value
    return result


def build_artifact_string(row: dict) -> str:
    """
    artifact 컬럼에 넣을 문자열 생성:
    'id:... | type:... | LastWriteTimestamp:... | tag:... | description:...'
    """
    id_val = row.get("id")
    type_val = row.get("type") or ""
    ts_val = row.get("lastwritetimestamp") or ""
    tag_val = row.get("tag") or ""
    desc_val = row.get("description") or ""

    return " | ".join([
        f"id:{id_val}",
        f"type:{type_val}",
        f"LastWriteTimestamp:{ts_val}",
        f"tag:{tag_val}",
        f"description:{desc_val}",
    ])


# =====================
# 2. SRUM 파이프라인용 함수
# =====================

def recreate_srum_target_table(conn, target_table: str):
    """
    SRUM 대표 TTP를 담을 artifact_srum_ttp 테이블을
    통합 스키마(id, src_id, artifact, tactic, ttp)로 재생성.
    """
    cur = conn.cursor()
    print(f"[+] 기존 {target_table} 테이블 삭제(DROP TABLE IF EXISTS)...")
    cur.execute(f"DROP TABLE IF EXISTS {target_table};")
    conn.commit()

    create_table_sql = f"""
    CREATE TABLE {target_table} (
        id SERIAL PRIMARY KEY,
        src_id INTEGER,
        artifact TEXT NOT NULL,
        tactic TEXT,
        ttp TEXT
    );
    """
    cur.execute(create_table_sql)
    conn.commit()
    cur.close()
    print(f"[+] 테이블 생성 완료: {target_table}")


def fetch_srum_candidates(conn, source_table: str):
    """
    artifact_all에서 SRUM / UserActivity 관련 행들을 가져온다.
    (나중에 필요하면 WHERE 절만 바꾸거나, 인자를 받아서 일반화 가능)
    """
    cur = conn.cursor(cursor_factory=DictCursor)

    select_sql = f"""
    SELECT id, type, lastwritetimestamp, tag, description
    FROM {source_table}
    WHERE
        description LIKE 'type : NLT_SRUM_AppResourceUseInfo%%'
        OR tag = 'UserActivity';
    """
    cur.execute(select_sql)
    rows = cur.fetchall()
    cur.close()

    print(f"[+] {source_table}에서 SRUM/UserActivity 후보 {len(rows)}개 조회")
    return [dict(r) for r in rows]


def build_srum_representatives(rows):
    """
    (ExeBase, SidType)별 대표 1개만 고르기.
    key: (ExeBase, SidType) → value: 대표 row(dict)
    """
    pattern_to_row = {}

    for row in rows:
        desc = row.get("description") or ""
        d = parse_description_to_dict(desc)

        exeinfo = d.get("ExeInfo", "")
        sidtype = d.get("SidType", "")
        exe_base = normalize_exeinfo(exeinfo)

        key = (exe_base, sidtype)

        # 아직 이 패턴이 없으면 첫 번째 행을 대표로 사용
        if key not in pattern_to_row:
            pattern_to_row[key] = row

    print(f"[+] 대표 패턴 개수 (ExeBase, SidType 기준): {len(pattern_to_row)}")
    return pattern_to_row


def insert_srum_representatives(conn, target_table: str, pattern_to_row: dict):
    """
    대표 row 들만 artifact_srum_ttp에 INSERT (tactic/ttp는 전부 NULL)
    """
    cur = conn.cursor()
    insert_sql = f"""
    INSERT INTO {target_table} (src_id, artifact, tactic, ttp)
    VALUES (%s, %s, %s, %s);
    """

    inserted = 0
    for key, row in pattern_to_row.items():
        src_id = row.get("id")
        artifact_text = build_artifact_string(row)

        tactic_value = None  # 지금은 비워둠 → DB에서 NULL
        ttp_value = None

        cur.execute(insert_sql, (src_id, artifact_text, tactic_value, ttp_value))
        inserted += 1

    conn.commit()
    cur.close()
    print(f"[+] 대표만 {inserted}개 행 {target_table}에 삽입 완료 (tactic/ttp는 전부 NULL)")


def run_srum_pipeline():
    """
    SRUM + UserActivity 대표 추출 → artifact_srum_ttp에 적재까지
    한 번에 실행하는 메인 파이프라인 함수.
    """
    conn = get_connection()

    try:
        # 1) 타겟 테이블 재생성
        recreate_srum_target_table(conn, TARGET_TABLE)

        # 2) SRUM / UserActivity 후보 행 SELECT
        rows = fetch_srum_candidates(conn, GENERAL_TABLE)

        # 3) (ExeBase, SidType) 별 대표 1개씩 선택
        pattern_to_row = build_srum_representatives(rows)

        # 4) 대표들만 artifact_srum_ttp에 INSERT
        insert_srum_representatives(conn, TARGET_TABLE, pattern_to_row)

    finally:
        conn.close()
        print("[+] 작업 완료, 연결 종료")


# =====================
# 3. 엔트리 포인트
# =====================

if __name__ == "__main__":
    # 지금은 SRUM 파이프라인만 실행하지만,
    # 나중에 Prefetch/Service/Registry 등 다른 아티팩트 파이프라인 함수도 여기서 호출하면 된다.
    run_srum_pipeline()
