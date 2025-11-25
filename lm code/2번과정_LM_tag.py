import json
import requests
import psycopg2
from psycopg2.extras import DictCursor

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

# Ollama 설정
OLLAMA_URL   = "http://localhost:11434/api/generate"
OLLAMA_MODEL = "cogito-2.1:671b-cloud"


# =========================
# 1. Ollama 관련 (프롬프트 동일하게 사용)
# =========================

SYSTEM_INSTRUCTION = """
넌 디지털 포렌식 전문가다.

너의 임무:
- 주어진 아티팩트(이벤트) **내용만** 보고, MITRE ATT&CK 기준으로 악성 여부를 판단한다.
- 추측으로 확대 해석하지 말고, 로그에 드러난 사실만 근거로 판단한다.
- 애매하거나, 일반적인 OS/드라이버/보안 제품/벤더 소프트웨어의 정상 동작 범주로 보이면 "정상"으로 본다.

출력 규칙은 반드시 아래 둘 중 하나만 사용해라.

1) 명백히 정상 동작으로 보이는 경우
   → 아래 JSON 형식 그대로 출력해라.
   {"technique_id": "NORMAL", "technique_name": "NORMAL"}

2) 악성 가능성이 있다고 판단되는 경우
   → MITRE ATT&CK Enterprise 기준으로 가장 가까운 기법 1개만 고르고,
      아래 JSON 형식으로 한 줄만 출력해라.
   {"technique_id": "Txxxx.xxx", "technique_name": "Technique Name"}

추가 설명, 자연어 문장, 코드블록, 줄바꿈은 절대 넣지 마라.
JSON 한 줄만 출력해야 한다.
""".strip()







def ask_ollama_http(prompt: str) -> str:
    """Ollama /api/generate 호출"""
    payload = {
        "model": OLLAMA_MODEL,
        "prompt": prompt,
        "stream": False,
    }
    res = requests.post(OLLAMA_URL, json=payload)

    if res.status_code != 200:
        print("Status:", res.status_code)
        print("Body:", res.text)

    res.raise_for_status()
    data = res.json()
    return data.get("response", "").strip()


def build_prompt_for_row(row) -> str:
    """
    artifact_srum_ttp + artifact_all JOIN 결과인 row를
    LLM에게 줄 프롬프트 문자열로 만든다.
    """
    type_val = row.get("type", "") or ""
    time_val = row.get("lastwritetimestamp", "") or ""
    desc_val = row.get("description", "") or ""
    tag_val  = row.get("tag", "") or ""

    user_part = f"""
아래는 디지털 포렌식 이벤트 한 건에 대한 정보이다.

[Event]
- type: {type_val}
- lastwritetimestamp: {time_val}
- description: {desc_val}
- tag: {tag_val}

위 이벤트 내용만 보고, 앞에서 설명한 규칙에 따라
반드시 JSON 한 줄만 출력해라.

- 설명 문장, 이유, 해설, 코드블록은 절대 쓰지 마라.
- 오직 JSON 한 줄만 써야 한다.
    """.strip()

    full_prompt = SYSTEM_INSTRUCTION + "\n\n" + user_part
    return full_prompt



def parse_llm_json(raw: str):
    """LLM 응답에서 JSON 한 줄만 뽑아 파싱"""
    raw = raw.strip()

    # 혹시 앞뒤에 이상한 문장이 붙어도 중괄호만 잘라서 시도
    if "{" in raw and "}" in raw:
        try:
            start = raw.index("{")
            end = raw.rindex("}") + 1
            raw = raw[start:end]
        except ValueError:
            pass

    try:
        data = json.loads(raw)
        mitre_id = data.get("technique_id", "UNKNOWN")
        ttp_name = data.get("technique_name", "Unknown")
    except json.JSONDecodeError:
        # 파싱 실패하면 응답 일부를 그냥 저장
        mitre_id = "PARSE_ERROR"
        ttp_name = raw[:200]

    return mitre_id, ttp_name


# =========================
# 2. DB 유틸
# =========================

def ensure_map_table_columns(conn):
    """
    artifact_srum_ttp에 tactic / ttp 컬럼이 없으면 추가.
    (있으면 그대로 둠)
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
            m.id  AS map_id,
            m.src_id AS src_id,
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


def update_mapping_row(conn, map_id: int, mitre_id: str, ttp_name: str):
    """
    LLM이 태깅한 결과를 artifact_srum_ttp에 다시 기록.
    """
    with conn.cursor() as cur:
        cur.execute(
            f"""
            UPDATE {MAP_TABLE}
            SET tactic = %s,
                ttp    = %s
            WHERE id = %s;
            """,
            (mitre_id, ttp_name, map_id)
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

            print(f"  - map_id={map_id}, src_id={src_id} 처리 중...")

            prompt = build_prompt_for_row(row)
            raw_answer = ask_ollama_http(prompt)
            mitre_id, ttp_name = parse_llm_json(raw_answer)

            print(f"    → mitre_id={mitre_id}, ttp={ttp_name}")
            update_mapping_row(conn, map_id, mitre_id, ttp_name)

            # 다음 루프 기준값 업데이트
            last_map_id = map_id

        print(f"[Batch 종료] 현재까지 처리한 마지막 map_id = {last_map_id}")

    conn.close()
    print("[+] 연결 종료, 작업 완료")


if __name__ == "__main__":
    main()
