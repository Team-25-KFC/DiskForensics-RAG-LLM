# -*- coding: utf-8 -*-
"""
artifact_all 테이블에서

1) SRUM(AppResourceUseInfo) / UserActivity 관련 아티팩트를 가져와
   실행 파일 이름(ExeBase) + 권한 컨텍스트(SidType) 기준으로 "대표"만 고르고,
   그 대표들을 artifact_srum_ttp 테이블에 넣는 파이프라인

2) RECmd BasicSystemInfo(시스템 정보) 관련 아티팩트를 가져와
   Description 기준으로 SYS_ENV_* 태그를 달고,
   그 결과를 artifact_systeminfo_ttp 테이블에 넣는 파이프라인

두 가지를 한 파일에 통합한 스크립트.

공통 스키마:
    - artifact_srum_ttp
    - artifact_systeminfo_ttp

두 테이블 모두:
    id SERIAL PRIMARY KEY,
    src_id INTEGER,
    artifact TEXT NOT NULL,
    tactic TEXT,
    ttp TEXT
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

GENERAL_TABLE = "artifact_all"              # 전체 아티팩트 메인 테이블

# 🎯 SRUM / SystemInfo 둘 다 이 한 테이블에 쌓이게 만든다
UNIFIED_TTP_TABLE = "artifact_env_ttp"      # 새로 통합해서 쓸 테이블 이름
SRUM_TARGET_TABLE = UNIFIED_TTP_TABLE
SYSTEMINFO_TARGET_TABLE = UNIFIED_TTP_TABLE


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
    SRUM / SystemInfo 둘 다 공용으로 사용.
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
# 2. SRUM 파이프라인 (단일 함수)
# =====================

def run_srum_pipeline():
    """
    SRUM + UserActivity 대표 추출 → artifact_env_ttp에 적재까지
    (여기서 테이블 DROP & CREATE 까지 담당)
    """
    conn = get_connection()

    try:
        cur = conn.cursor()

        # 1) 타겟 테이블 재생성
        print(f"[+] 기존 {SRUM_TARGET_TABLE} 테이블 삭제(DROP TABLE IF EXISTS)...")
        cur.execute(f"DROP TABLE IF EXISTS {SRUM_TARGET_TABLE};")
        conn.commit()

        create_table_sql = f"""
        CREATE TABLE {SRUM_TARGET_TABLE} (
            id SERIAL PRIMARY KEY,
            src_id INTEGER,
            artifact TEXT NOT NULL,
            tactic TEXT,
            ttp TEXT
        );
        """
        cur.execute(create_table_sql)
        conn.commit()
        print(f"[+] 테이블 생성 완료: {SRUM_TARGET_TABLE}")

        # 이하 SRUM 후보 SELECT, 대표 선정, INSERT 부분은 그대로 유지
        ...


        # 2) SRUM / UserActivity 후보 행 SELECT
        cur = conn.cursor(cursor_factory=DictCursor)
        select_sql = f"""
        SELECT id, type, lastwritetimestamp, tag, description
        FROM {GENERAL_TABLE}
        WHERE
            description LIKE 'type : NLT_SRUM_AppResourceUseInfo%%'
            OR tag = 'UserActivity';
        """
        cur.execute(select_sql)
        rows = [dict(r) for r in cur.fetchall()]
        cur.close()

        print(f"[+] {GENERAL_TABLE}에서 SRUM/UserActivity 후보 {len(rows)}개 조회")

        # 3) (ExeBase, SidType) 별 대표 1개씩 선택
        pattern_to_row = {}
        for row in rows:
            desc = row.get("description") or ""
            d = parse_description_to_dict(desc)

            exeinfo = d.get("ExeInfo", "")
            sidtype = d.get("SidType", "")
            exe_base = normalize_exeinfo(exeinfo)

            key = (exe_base, sidtype)

            if key not in pattern_to_row:
                pattern_to_row[key] = row

        print(f"[+] 대표 패턴 개수 (ExeBase, SidType 기준): {len(pattern_to_row)}")

        # 4) 대표들만 artifact_srum_ttp에 INSERT
        cur = conn.cursor()
        insert_sql = f"""
        INSERT INTO {SRUM_TARGET_TABLE} (src_id, artifact, tactic, ttp)
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
        print(f"[+] 대표만 {inserted}개 행 {SRUM_TARGET_TABLE}에 삽입 완료 (tactic/ttp는 전부 NULL)")

    finally:
        conn.close()
        print("[+] SRUM 파이프라인 작업 완료, 연결 종료")

# =====================
# 3. SystemInfo(BasicSystemInfo) 파이프라인 (단일 함수)
# =====================
def run_systeminfo_pipeline():
    """
    SystemInfo(레지스트리 기반 시스템 환경 정보, tag='system') → SYS_ENV_* 태그 달기 → 
    SRUM과 같은 통합 테이블(artifact_env_ttp)에 INSERT.

    ⚠ 여기서는 테이블을 DROP/CREATE 하지 않는다.
       → 테이블 초기화는 SRUM 파이프라인(run_srum_pipeline)이 한 번만 담당.
    """
    conn = get_connection()

    try:
        # 1) artifact_all에서 SystemInfo(환경 레지스트리) 관련 행들을 가져온다.
        #    → RECmd BasicSystemInfo 결과는 tag='system' 으로 들어가 있다고 가정
        cur = conn.cursor(cursor_factory=DictCursor)
        select_sql = f"""
        SELECT id, type, lastwritetimestamp, tag, description
        FROM {GENERAL_TABLE}
        WHERE tag = 'system';
        """
        cur.execute(select_sql)
        rows = [dict(r) for r in cur.fetchall()]
        cur.close()

        print(f"[+] {GENERAL_TABLE}에서 SystemInfo(tag='system') 후보 {len(rows)}개 조회")

        if not rows:
            print("[!] SystemInfo 후보가 없습니다. tag='system' 으로 들어갔는지 확인하세요.")
            return

        # 2) 태깅 후 INSERT (SRUM과 같은 통합 테이블에 쌓기)
        cur = conn.cursor()
        insert_sql = f"""
        INSERT INTO {SYSTEMINFO_TARGET_TABLE} (src_id, artifact, tactic, ttp)
        VALUES (%s, %s, %s, %s);
        """

        total = 0
        ttp_counter = {}

        for row in rows:
            total += 1
            src_id = row.get("id")
            type_val = row.get("type") or ""
            t = type_val.strip()

            # ==========================
            # type 기준 SYS_ENV_* 분류
            # ==========================
            if t.startswith("ProfileList"):
                ttp_tag = "SYS_ENV_ACCOUNT"

            elif t.startswith("NetworkList") or t.startswith("NetworkCards") or t.startswith("Tcpip"):
                ttp_tag = "SYS_ENV_NETWORK"

            elif t in ("Windows Defender Exclusions", "Defender Real-Time Protection", "Shares"):
                ttp_tag = "SYS_ENV_SECURITY"

            elif t in (
                "SystemBootDevice",
                "SystemPartition",
                "FirmwareBootDevice",
                "Mounted Devices",
                "DisableDeleteNotification",
                "NtfsEncryptPagingFile",
            ):
                ttp_tag = "SYS_ENV_BOOT_DISK"

            elif t == "Session Manager Environment":
                ttp_tag = "SYS_ENV_MISC"

            else:
                # 나머지는 전부 OS/기본 시스템 정보 (Domain SID, BuildBranch, BuildLab, CurrentVersion 등)
                ttp_tag = "SYS_ENV_OS"
            # ==========================

            ttp_counter[ttp_tag] = ttp_counter.get(ttp_tag, 0) + 1

            artifact_text = build_artifact_string(row)
            tactic_value = "SystemInfo"
            ttp_value = ttp_tag

            cur.execute(insert_sql, (src_id, artifact_text, tactic_value, ttp_value))

        conn.commit()
        cur.close()

        print("\n[+] SystemInfo 태깅 결과 요약")
        print(f"  - 전체 행 수        : {total}")
        print(f"  - 태그 못 붙은 행 수: 0  (전부 SYS_ENV_* 중 하나로 분류됨)")

        print("\n[+] ttp(=SYS_ENV_*) 분포")
        for k in sorted(ttp_counter.keys()):
            print(f"  - {k:16s} : {ttp_counter[k]} 개")

    finally:
        conn.close()
        print("[+] SystemInfo 파이프라인 작업 완료, 연결 종료")


# =====================
# 4. 엔트리 포인트
# =====================

if __name__ == "__main__":
    # 1) SRUM 대표 패턴 추출
    run_srum_pipeline()

    # 2) BasicSystemInfo 시스템 정보 태깅
    run_systeminfo_pipeline()
