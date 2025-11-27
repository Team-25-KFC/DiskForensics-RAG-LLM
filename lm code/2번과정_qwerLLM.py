import json
import time
import requests
import psycopg2
from psycopg2.extras import DictCursor

# =========================
# 0. ??
# =========================

DB_CONFIG = {
    "host": "localhost",
    "dbname": "forensic_db",
    "user": "postgres",
    "password": "admin123",
}

# ?? ???? & ?? ???
MAP_TABLE = "artifact_env_ttp"   # LLM ?? ??? ???? ???(??? ??? ???)
SRC_TABLE = "artifact_all"       # ?? ?? ???? ???

# ?? ?? (? ?? ? ?? LLM? ???)
BATCH_SIZE = 20

# LM Studio ??
LMSTUDIO_URL = "http://localhost:1234/v1/chat/completions"
MODEL_NAME   = "qwen/qwen3-4b-thinking-2507"


# =========================
# 1. LM Studio - ATT&CK ?? ??
# =========================

def ask_local_llm_for_attack(artifact: str) -> dict:
    """
    ???? ?? ???? ?? ATT&CK technique_id? technique_name? ?? ????.
    LLM? ?? ?? "Unknown"? ???? ????.
    """
    format_instruction = """
?? ???? ?? ?? ???.

?? ???? ??? ?? MITRE ATT&CK ?? ID? ??? ???.
??? Unknown?? ??.

?? ??? JSON ???? ?? (????/??/?? ??)
{
  "technique_id": "T#### ?? ?? Unknown",
  "technique_name": "?? ?? ?? Unknown",
  "reason": "??? ??? ??? ???? 1~3??"
}
""".strip()

    full_prompt = f"""{format_instruction}

[Artifact]
{artifact}
"""

    payload = {
        "model": MODEL_NAME,
        "messages": [
            {"role": "system", "content": "?? ???? ?? ?? ????."},
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
        technique_id = (obj.get("technique_id") or "").strip() or "Unknown"
        technique_name = (obj.get("technique_name") or "").strip() or "Unknown"
        reason = (obj.get("reason") or "").strip()
    except Exception:
        print("[WARN] LLM JSON ?? ??:", content)
        technique_id = "Unknown"
        technique_name = "Unknown"
        reason = ""

    return {
        "technique_id": technique_id,
        "technique_name": technique_name,
        "reason": reason,
    }


# =========================
# 2. DB ??
# =========================

def ensure_map_table_columns(conn):
    """
    artifact_env_ttp? tactic / ttp ??? ??? ????.
    tactic: technique_id (?: T1016, Unknown)
    ttp   : technique_name (?: System Network Configuration Discovery)
    """
    with conn.cursor() as cur:
        cur.execute(f"""
            ALTER TABLE {MAP_TABLE}
            ADD COLUMN IF NOT EXISTS tactic TEXT,
            ADD COLUMN IF NOT EXISTS ttp    TEXT;
        """)
        conn.commit()


def fetch_mapping_batch(conn, batch_size: int):
    """
    artifact_env_ttp + artifact_all JOIN??
    ?? tactic? ???? ?? ????? batch_size ?? ????.

    ?? ?: DictRow ???
      - map_id  : artifact_env_ttp.id
      - src_id  : artifact_env_ttp.src_id (= artifact_all.id)
      - type, lastwritetimestamp, description, tag : artifact_all ?? ???
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
            (m.tactic IS NULL OR m.tactic = '')
        ORDER BY m.id
        LIMIT %s;
    """
    with conn.cursor(cursor_factory=DictCursor) as cur:
        cur.execute(query, (batch_size,))
        rows = cur.fetchall()
        return rows


def update_mapping_row(conn, map_id: int, technique_id: str, technique_name: str):
    """
    LLM ??? artifact_env_ttp? ????.
    tactic  = technique_id (?: T1016, Unknown)
    ttp     = technique_name (?: System Network Configuration Discovery, Unknown)
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
# 3. ?? ?? ??
# =========================

def main():
    conn = psycopg2.connect(**DB_CONFIG)
    print("[+] PostgreSQL ?? ??")

    ensure_map_table_columns(conn)
    processed_total = 0

    while True:
        batch = fetch_mapping_batch(conn, BATCH_SIZE)
        if not batch:
            print("? ?? ??? ?? ????? ????. ?????.")
            break

        print(f"\n[Batch 시작] 비어있는 tactic row {len(batch)}건 처리")

        for row in batch:
            map_id = row["map_id"]
            src_id = row["src_id"]
            desc   = row.get("description", "") or ""
            type_v = row.get("type", "") or ""
            time_v = row.get("lastwritetimestamp", "") or ""

            artifact_str = desc
            if not artifact_str:
                artifact_str = f"{type_v}	{time_v}"

            print(f"  - map_id={map_id}, src_id={src_id}")
            t_start = time.perf_counter()

            llm_result = ask_local_llm_for_attack(artifact_str)
            technique_id = llm_result["technique_id"] or "Unknown"
            technique_name = llm_result["technique_name"] or "Unknown"

            elapsed = time.perf_counter() - t_start

            print(f"    technique_id   : {technique_id}")
            print(f"    technique_name : {technique_name}")
            # print(f"    elapsed_sec    : {elapsed:.3f}")  # ???? ?? ??

            update_mapping_row(conn, map_id, technique_id, technique_name)
            processed_total += 1

        print(f"[Batch ??] ?? ?? ??: {len(batch)}? / ??: {processed_total}?")

    conn.close()
    print("[+] ?? ??, ?? ??")


if __name__ == "__main__":
    main()
