import json
from typing import Dict, Any, Tuple, List

import psycopg2
from psycopg2.extras import DictCursor

from langflow.custom.custom_component.component import Component
from langflow.io import HandleInput, StrInput, BoolInput, Output
from langflow.schema.message import Message


# ========================================
# 0. DB 설정 & 공통 상수
# ========================================

DB_CONFIG = {
    "host": "localhost",
    "dbname": "forensic_db",
    "user": "postgres",
    "password": "admin123",
}

# 결과 저장 테이블
RESULT_TABLE_DEFAULT = "forensic_keyword_results"

# LLM 태그 카테고리
CATEGORY_KEYS = [
    "ARTIFACT",
    "EVENT",
    "AREA",
    "SEC",
    "FORMAT",
    "ACT",
    "TIME",
    "STATE",
]


# ========================================
# 1. 태그 / 시간 필터 정규화 + SQL 빌더
# ========================================

def normalize_tags(llm_result: Dict[str, Any]) -> Dict[str, list]:
    """
    LLM 응답에서 태그 부분만 표준화해서 꺼내는 함수.

    지원 형식 1) 새 형식:
        {
          "tags": {
            "ARTIFACT": [...],
            "EVENT": [...],
            ...
          },
          ...
        }

    지원 형식 2) 옛 형식:
        {
          "ARTIFACT": [...],
          "EVENT": [...],
          ...
        }

    둘 중 어떤 형식이든 받아서 항상:
        {
          "ARTIFACT": [...],
          "EVENT": [...],
          ...
        }
    형태로 맞춰서 반환.
    """
    if "tags" in llm_result and isinstance(llm_result["tags"], dict):
        tags = llm_result["tags"]
        return {cat: tags.get(cat, []) or [] for cat in CATEGORY_KEYS}

    tags: Dict[str, list] = {}
    for cat in CATEGORY_KEYS:
        values = llm_result.get(cat, []) or []
        if not isinstance(values, list):
            values = []
        tags[cat] = values
    return tags


def normalize_time_filter(llm_result: Dict[str, Any]) -> Dict[str, Any]:
    """
    LLM 응답에서 time_filter를 꺼내 표준화.

    반환 형식:
        {
          "field": "lastwritetimestamp",
          "from": <str or None>,
          "to": <str or None>,
          "original_text": <str or None>,
          "mode": "none" | "day" | "range" | "point"
        }
    """
    tf = llm_result.get("time_filter")
    if not isinstance(tf, dict):
        tf = {}

    return {
        "field": tf.get("field", "lastwritetimestamp"),
        "from": tf.get("from"),
        "to": tf.get("to"),
        "original_text": tf.get("original_text"),
        "mode": (tf.get("mode") or "none").lower(),
    }


def build_sql_from_llm(
    llm_result: Dict[str, Any],
    table_name: str = "artifact_all",
    columns: str = "type,lastwritetimestamp,description,tag",
) -> Tuple[str, Dict[str, Any]]:

    tags = normalize_tags(llm_result)
    time_filter = normalize_time_filter(llm_result)

    # 일단 핵심 카테고리만 AND 필터로 사용 (너무 빡세지 않게)
    HARD_FILTER_CATEGORIES = ["ARTIFACT", "EVENT", "AREA", "FORMAT", "ACT"]

    select_sql = f"""
SELECT
  {columns}
FROM {table_name}
"""

    where_clauses: List[str] = []
    params: Dict[str, Any] = {}

    for cat in HARD_FILTER_CATEGORIES:
        values = tags.get(cat, []) or []
        if not values:
            continue

        param_name = f"{cat.lower()}_list"

        if cat == "ARTIFACT":
            # ✅ ARTIFACT는 type 이나 tag 둘 중 하나에 들어있으면 매칭
            clause = (
                f"(type = ANY(%({param_name})s) "
                f"OR string_to_array(tag, ',') && %({param_name})s)"
            )
        else:
            # 나머지는 기존처럼 tag에서만 찾기
            clause = f"string_to_array(tag, ',') && %({param_name})s"

        where_clauses.append(clause)
        params[param_name] = values

    # (옵션) time_filter는 나중에 진짜 Timestamp 파싱할 때 붙일 수 있음
    time_mode = time_filter.get("mode", "none")
    tf_from = time_filter.get("from")
    tf_to = time_filter.get("to")

    if time_mode != "none" and tf_from and tf_to:
        where_clauses.append("lastwritetimestamp BETWEEN %(time_from)s AND %(time_to)s")
        params["time_from"] = tf_from
        params["time_to"] = tf_to

    if where_clauses:
        where_sql = "WHERE " + "\n  AND ".join(where_clauses)
    else:
        where_sql = ""

    order_sql = "\nORDER BY lastwritetimestamp;"

    full_sql = select_sql + where_sql + order_sql
    full_sql = "\n".join(
        line.rstrip()
        for line in full_sql.splitlines()
        if line.strip() != ""
    )

    return full_sql, params



# ========================================
# 2. SQL 실행 + forensic_keyword_results 저장 로직
# ========================================

def ensure_result_table(conn, table_name: str, reset: bool = False):
    """
    결과 테이블이 없으면 생성하고,
    reset=True 이면 내용 TRUNCATE.
    """
    create_sql = f"""
    CREATE TABLE IF NOT EXISTS {table_name} (
        id                  SERIAL PRIMARY KEY,
        type                TEXT,
        lastwritetimestamp  TEXT,
        description         TEXT,
        tag                 TEXT
    );
    """
    with conn.cursor() as cur:
        cur.execute(create_sql)
        if reset:
            cur.execute(f"TRUNCATE TABLE {table_name};")
    conn.commit()


def summarize_result_table(conn, table_name: str, limit: int = 20) -> str:
    """
    forensic_keyword_results 테이블의 전체 행 수 + 최근 일부 행 요약.
    """
    lines: List[str] = []
    with conn.cursor(cursor_factory=DictCursor) as cur:
        cur.execute(f"SELECT COUNT(*) AS cnt FROM {table_name};")
        cnt = cur.fetchone()["cnt"]
        lines.append(f"결과 테이블 '{table_name}' 총 행 수: {cnt}")

        cur.execute(
            f"""
            SELECT id, type, lastwritetimestamp, description, tag
            FROM {table_name}
            ORDER BY id DESC
            LIMIT %s;
            """,
            (limit,),
        )
        rows = cur.fetchall()

    lines.append(f"최근 {limit}개 결과 (id / type / time / tag / desc):")
    for r in rows:
        header = (
            f"[id={r['id']}] type='{r['type']}' "
            f"| time='{r['lastwritetimestamp']}' "
            f"| tag='{r['tag']}'"
        )
        body = f"  desc='{r['description']}'"
        lines.append(header)
        lines.append(body)

    return "\n".join(lines)


def run_tag_query_and_save(
    llm_result: Dict[str, Any],
    table_name: str = "artifact_all",
    result_table: str = RESULT_TABLE_DEFAULT,
    reset_table: bool = False,
    debug_sql: bool = True,
) -> str:
    """
    핵심 로직:
      - LLM 태그 JSON(dict)을 받아서
      - artifact_all 에 대해 SELECT SQL 생성
      - forensic_keyword_results 에 INSERT ... SELECT
      - 요약 문자열 반환
    """
    # 1) SQL / params 생성
    sql_select, params = build_sql_from_llm(
        llm_result,
        table_name=table_name,
        columns="type,lastwritetimestamp,description,tag",
    )

    # INSERT ... SELECT 로 감싸기
    insert_sql = (
        f"INSERT INTO {result_table} (type,lastwritetimestamp,description,tag)\n"
        + sql_select
    )

    # 디버깅용
    if debug_sql:
        print("========== [ForensicTagQuery] Generated SELECT SQL ==========")
        print(sql_select)
        print("---------- params ----------")
        print(json.dumps(params, ensure_ascii=False, indent=2))

    # 2) DB 연결
    conn = psycopg2.connect(**DB_CONFIG)
    conn.autocommit = False

    try:
        # 결과 테이블 준비
        ensure_result_table(conn, result_table, reset=reset_table)

        # 3) INSERT ... SELECT 실행
        with conn.cursor() as cur:
            cur.execute(insert_sql, params)
            inserted = cur.rowcount

        conn.commit()

        # 4) 요약 조회
        summary_text = summarize_result_table(conn, result_table, limit=20)

        full_summary = [
            f"[INFO] INSERT된 행 수: {inserted}",
            "",
            summary_text,
        ]
        return "\n".join(full_summary)

    except Exception as e:
        conn.rollback()
        return f"[ERROR] run_tag_query_and_save 중 오류: {e}"
    finally:
        conn.close()


# ========================================
# 3. LangFlow 커스텀 컴포넌트
# ========================================

class ForensicTagQueryAndSave(Component):
    """
    ForensicTagQueryAndSave

    역할:
      - LLM 노드에서 나온 Message/Data/Text 안의 JSON(태그)을 입력으로 받는다.
      - JSON 파싱 → 태그 기반 SQL 생성 → artifact_all 검색
      - forensic_keyword_results 테이블에 INSERT ... SELECT
      - 결과 요약을 Message(text=...) 형태로 반환한다.

    플로우 예시:
      LLM (태그 추천) → ForensicTagQueryAndSave → ChatOutput
    """

    display_name = "Forensic Tag Query & Save"
    description = (
        "LLM이 생성한 포렌식 태그 JSON을 기반으로 artifact_all을 조회하고, "
        "결과를 forensic_keyword_results 테이블에 저장한 뒤 요약을 반환합니다."
    )
    icon = "Database"
    name = "ForensicTagQueryAndSave"

    inputs = [
        HandleInput(
            name="input_value",
            display_name="LLM Tag JSON",
            info="LLM이 출력한 태그 JSON이 들어 있는 Message/Data/Text.",
            input_types=["Message", "Data", "Text"],
            required=True,
        ),
        StrInput(
            name="table_name",
            display_name="Source Table Name",
            info="검색을 수행할 테이블 이름 (기본: artifact_all).",
            required=False,
            value="artifact_all",
        ),
        StrInput(
            name="result_table",
            display_name="Result Table Name",
            info="검색 결과를 저장할 테이블 이름.",
            required=False,
            value=RESULT_TABLE_DEFAULT,
        ),
        BoolInput(
            name="reset_table",
            display_name="Reset Result Table (TRUNCATE)",
            info="실행 전에 결과 테이블 내용을 모두 비울지 여부.",
            value=False,
            required=False,
        ),
        BoolInput(
            name="debug_sql",
            display_name="Print Debug SQL",
            info="콘솔에 생성된 SQL과 params를 출력할지 여부.",
            value=True,
            required=False,
        ),
    ]

    outputs = [
        Output(
            display_name="Summary",
            name="summary",
            method="run",
            output_type="Message",  # ChatOutput과 잘 맞도록 Message 타입
        ),
    ]

    # --------- 내부 유틸: Message/Data/Text → 문자열 ---------
    def _extract_text_from_input(self, input_value: Any) -> str:
        if isinstance(input_value, str):
            return input_value

        if isinstance(input_value, dict):
            for key in ["text", "content", "data", "message"]:
                if key in input_value and isinstance(input_value[key], str):
                    return input_value[key]
            return json.dumps(input_value, ensure_ascii=False)

        text_attr = getattr(input_value, "text", None)
        if isinstance(text_attr, str):
            return text_attr

        return str(input_value)

    # --------- LangFlow에서 호출되는 메인 메서드 ---------
    def run(self, input_value: Any = None, **kwargs) -> Message:
        """
        LangFlow가 이 컴포넌트를 실행할 때 호출되는 메서드.
        - input_value: 앞 노드에서 넘어온 Message/Data/Text
        - 기타 파라미터는 self.table_name 등으로 접근.
        """
        raw = self._extract_text_from_input(
            input_value if input_value is not None else getattr(self, "input_value", "")
        )
        raw = (raw or "").strip()

        if not raw:
            return Message(text="[ERROR] 입력이 비어 있어 태그 JSON을 파싱할 수 없습니다.")

        # ```json ... ``` 형태일 때 코드블럭 제거
        if raw.startswith("```"):
            first_brace = raw.find("{")
            last_brace = raw.rfind("}")
            if first_brace != -1 and last_brace != -1 and last_brace > first_brace:
                raw = raw[first_brace:last_brace + 1].strip()

        # JSON 파싱
        try:
            llm_result = json.loads(raw)
        except json.JSONDecodeError as e:
            msg = (
                "[ERROR] 태그 JSON 파싱 실패: "
                + str(e)
                + "\n\nRAW INPUT (앞 200자):\n"
                + repr(raw[:200])
            )
            return Message(text=msg)

        table_name = getattr(self, "table_name", "artifact_all")
        result_table = getattr(self, "result_table", RESULT_TABLE_DEFAULT)
        reset_table = bool(getattr(self, "reset_table", False))
        debug_sql = bool(getattr(self, "debug_sql", True))

        summary_text = run_tag_query_and_save(
            llm_result=llm_result,
            table_name=table_name,
            result_table=result_table,
            reset_table=reset_table,
            debug_sql=debug_sql,
        )

        return Message(text=summary_text)
