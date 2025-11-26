import json
import time
import difflib
import requests
import psycopg2
from psycopg2.extras import DictCursor

from attack_id_to_name import ATTACK_ID_TO_NAME  # MITRE ID ↔ 이름 매핑 딕셔너리

# =========================
# 0. 설정
# =========================

DB_CONFIG = {
    "host": "localhost",
    "dbname": "forensic_db",
    "user": "postgres",
    "password": "admin123",
}

# 대표 아티팩트 & 원본 테이블
MAP_TABLE = "artifact_srum_ttp"   # LLM이 태깅할 대상 (대표만 모아둔 테이블)
SRC_TABLE = "artifact_all"        # 원본 전체 아티팩트 테이블

# 배치 크기 (한 번에 몇 개씩 LLM에 보낼지)
BATCH_SIZE = 20

# LM Studio 설정
LMSTUDIO_URL = "http://localhost:1234/v1/chat/completions"
MODEL_NAME   = "qwen/qwen3-4b-thinking-2507"


# =========================
# 1. LM Studio + 이름 매핑
# =========================

def ask_local_llm_for_rough_name(artifact: str) -> dict:
    """
    아티팩트 한 줄(또는 한 이벤트 설명 문자열)을 넣으면,
    LLM이 'rough_name'(기법 이름 비슷한 영문 한 줄)과
    'reason'(한국어 이유)을 JSON으로 돌려준다.
    여기서는 MITRE ID는 절대 말하게 하지 않는다.
    """
    format_instruction = """
너는 디지털 포렌식 분석 도우미야.
너는 MITRE ATT&CK ID 번호를 정확히 모를 수 있다.
따라서, 아래 아티팩트에 대해 "정확한 ID를 말하려고 하지 말고",

1) 이 아티팩트가 나타내는 공격/행동/기법을
   MITRE ATT&CK 기법 이름과 비슷한 "영문 한 줄 이름"으로 적어라.
   예: "System Network Configuration Discovery", "Modify Registry",
       "Create or Modify System Process", "Exfiltration Over C2 Channel" 등.

2) 왜 그렇게 판단했는지 한국어로 간단한 이유를 1~3문장 정도로 적어라.

⚠️ 반드시 아래 JSON 형식으로만 출력해.
설명 문장, 주석, 코드블록( ``` ) 절대 붙이지 마.

형식:
{
  "rough_name": "여기에 영문 한 줄 이름",
  "reason": "왜 그렇게 판단했는지 한국어로 1~3문장 설명"
}
""".strip()

    full_prompt = f"""{format_instruction}

[Artifact]
{artifact}
"""

    payload = {
        "model": MODEL_NAME,
        "messages": [
            {"role": "system", "content": "너는 디지털 포렌식 및 보안 전문가야."},
            {"role": "user", "content": full_prompt},
        ],
        "temperature": 0.1,
        "stream": False,
    }

    resp = requests.post(LMSTUDIO_URL, json=payload)
    resp.raise_for_status()

    content = resp.json()["choices"][0]["message"]["content"].strip()

    try:
        obj = json.loads(content)
        rough_name = obj.get("rough_name", "").strip()
        reason = obj.get("reason", "").strip()
    except Exception:
        print("[WARN] LLM 출력이 JSON이 아님:", content)
        rough_name = ""
        reason = ""

    return {
        "rough_name": rough_name,
        "reason": reason,
    }


def find_best_attack_id_by_name(rough_name: str, threshold: float = 0.5) -> str:
    """
    LLM이 준 rough_name(기법 이름 비슷한 영문 한 줄)을
    ATTACK_ID_TO_NAME 딕셔너리와 비교해서
    가장 비슷한 technique_id를 고른다.

    - substring 일치 시 점수 1.0
    - 그 외에는 difflib 시퀀스 유사도 사용
    - best_score < threshold 이면 "Unknown" 반환
    """
    if not rough_name:
        return "Unknown"

    q = rough_name.lower().strip()

    best_id = "Unknown"
    best_score = 0.0

    for tid, tname in ATTACK_ID_TO_NAME.items():
        name_lower = tname.lower()

        # 1) 부분 문자열로 완전히 포함되면 최우선
        if q in name_lower or name_lower in q:
            score = 1.0
        else:
            # 2) 그 외에는 문자열 유사도
            score = difflib.SequenceMatcher(a=q, b=name_lower).ratio()

        if score > best_score:
            best_score = score
            best_id = tid

    if best_score < threshold:
        return "Unknown"

    return best_id


# =========================
# 2. DB 유틸
# =========================

def ensure_map_table_columns(conn):
    """
    artifact_srum_ttp에 tactic / ttp 컬럼이 없으면 추가.
    (있으면 그대로 둠)
    tactic  : technique_id (예: T1016, Unknown 등)
    ttp     : technique_name (예: System Network Configuration Discovery)
    """
    with conn.cursor() as cur:
        cur.execute(f"""
            ALTER TABLE {MAP_TABLE}
            ADD COLUMN IF NOT EXISTS tactic TEXT,
            ADD COLUMN IF NOT EXISTS ttp    TEXT;
        """)
        conn.commit()


def get_last_processed_map_id(conn) -> int:
    """
    이미 tactic이 채워진 행들 중에서, id의 최댓값을 기준으로
    '어디까지 처리했는지'를 판단한다.
    """
    with conn.cursor() as cur:
        cur.execute(f"""
            SELECT COALESCE(MAX(id), 0)
            FROM {MAP_TABLE}
            WHERE tactic IS NOT NULL AND tactic <> '';
        """)
        (max_id,) = cur.fetchone()
        return max_id or 0


def fetch_mapping_batch(conn, last_map_id: int, batch_size: int):
    """
    artifact_srum_ttp + artifact_all JOIN해서
    아직 tactic이 비어있는 대표 아티팩트들만 가져온다.

    반환 값: DictRow 리스트
      - map_id  : artifact_srum_ttp.id
      - src_id  : artifact_srum_ttp.src_id (= artifact_all.id)
      - type, lastwritetimestamp, description, tag : artifact_all 에서 가져옴
    """
    query = f"""
        SELECT
            m.id      AS map_id,
            m.src_id  AS src_id,
            a.type,
            a.lastwritetimestamp,
            a.description,
            a.tag
        FROM {MAP_TABLE} AS m
        JOIN {SRC_TABLE} AS a
          ON a.id = m.src_id
        WHERE
            m.id > %s
            AND (m.tactic IS NULL OR m.tactic = '')
        ORDER BY m.id
        LIMIT %s;
    """
    with conn.cursor(cursor_factory=DictCursor) as cur:
        cur.execute(query, (last_map_id, batch_size))
        rows = cur.fetchall()
        return rows


def update_mapping_row(conn, map_id: int, technique_id: str, technique_name: str):
    """
    LLM + 매핑 결과를 artifact_srum_ttp에 기록.
    tactic  ← technique_id (예: T1016, Unknown)
    ttp     ← technique_name (예: System Network Configuration Discovery, Unknown)
    """
    with conn.cursor() as cur:
        cur.execute(
            f"""
            UPDATE {MAP_TABLE}
            SET tactic = %s,
                ttp    = %s
            WHERE id = %s;
            """,
            (technique_id, technique_name, map_id)
        )
        conn.commit()


# =========================
# 3. 메인 배치 루프
# =========================

def main():
    conn = psycopg2.connect(**DB_CONFIG)
    print("[+] PostgreSQL 연결 성공")

    ensure_map_table_columns(conn)

    last_map_id = get_last_processed_map_id(conn)
    print(f"이전까지 tactic이 채워진 마지막 map_id: {last_map_id}")

    while True:
        batch = fetch_mapping_batch(conn, last_map_id, BATCH_SIZE)
        if not batch:
            print("더 이상 처리할 대표 아티팩트가 없습니다. 종료합니다.")
            break

        print(f"\n[Batch 시작] map_id > {last_map_id} 인 행 {len(batch)}개 처리")

        for row in batch:
            map_id = row["map_id"]
            src_id = row["src_id"]
            desc   = row.get("description", "") or ""
            type_v = row.get("type", "") or ""
            time_v = row.get("lastwritetimestamp", "") or ""

            # 🔹 실질적으로 LLM에게 던질 아티팩트 문자열
            artifact_str = desc
            if not artifact_str:
                artifact_str = f"{type_v}\t{time_v}"

            print(f"  - map_id={map_id}, src_id={src_id}")
            # print(f"    artifact: {artifact_str}")  # 필요하면 디버깅용으로 다시 활성화

            t_start = time.perf_counter()

            # 1) LLM에게 rough_name + reason 받기
            llm_result = ask_local_llm_for_rough_name(artifact_str)
            rough_name = llm_result["rough_name"]
            # reason     = llm_result["reason"]  # 지금은 reason 안 씀

            # 2) rough_name 기반으로 가장 비슷한 ATT&CK ID 찾기
            technique_id = find_best_attack_id_by_name(rough_name)

            # 3) ID → 공식 이름 매핑 (없으면 Unknown)
            technique_name = ATTACK_ID_TO_NAME.get(technique_id, "Unknown")

            elapsed = time.perf_counter() - t_start

            # ✅ 여기서부터는 "아이디랑 이름만" 출력
            print(f"    technique_id   : {technique_id}")
            print(f"    technique_name : {technique_name}")
            # print(f"    elapsed_sec    : {elapsed:.3f}")  # 시간도 보고 싶으면 이 줄만 다시 살리면 됨

            # 4) DB에 저장 (Unknown 이라도 그대로 저장)
            update_mapping_row(conn, map_id, technique_id, technique_name)

            # 다음 루프 기준값 업데이트
            last_map_id = map_id

        print(f"[Batch 종료] 현재까지 처리한 마지막 map_id = {last_map_id}")

    conn.close()
    print("[+] 연결 종료, 작업 완료")


if __name__ == "__main__":
    main()
