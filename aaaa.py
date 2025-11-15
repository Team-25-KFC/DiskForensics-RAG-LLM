import re
import threading
import psycopg2
from psycopg2.extras import DictCursor
import traceback

# ========================================
# 0. DB 설정
# ========================================
DB_CONFIG = {
    "host": "localhost",
    "dbname": "forensic_db",
    "user": "postgres",
    "password": "admin123",
}

# 결과 저장 테이블
RESULT_TABLE = "forensic_keyword_results"

# ========================================
# 1. 검색 대상 테이블 공통 컬럼 이름
#    └ 네 DB 기준: id, type, lastwritetimestamp, description, tag
# ========================================
ID_COLUMN = "id"                  # PK / unique id 컬럼
TEXT_COLUMN = "description"       # 검색할 텍스트 컬럼
EVENT_ID_COLUMN = "tag"           # 이벤트 ID / 태그 컬럼
TYPE_COLUMN = "type"              # 원본 type 컬럼
TIME_COLUMN = "lastwritetimestamp"  # 원본 lastwritetimestamp 컬럼

# ========================================
# 2. TAGS (pk + text 안에 Keywords)
# ========================================
TAGS = [
{
    "category": "System",
    "subcategory": "OS_Info",
    "description": "운영체제 버전, 빌드, 설치 정보 및 등록자 정보를 확인한다.",
    "keywords": [
      "Microsoft\\Windows NT\\CurrentVersion AND ProductName",
      "Microsoft\\Windows NT\\CurrentVersion AND EditionID",
      "Microsoft\\Windows NT\\CurrentVersion AND BuildLabEx",
      "Microsoft\\Windows NT\\CurrentVersion AND InstallDate",
      "Microsoft\\Windows NT\\CurrentVersion AND RegisteredOwner",
      "Microsoft\\Windows NT\\CurrentVersion AND ProductId"
    ]
    }
]

# ========================================
# TAG별 요약 저장용 전역 변수
#  - 각 TAG가 어디서 몇 개를 찾았는지 기록
# ========================================
TAG_SUMMARY = {}
SUMMARY_LOCK = threading.Lock()


# ========================================
# 공통 로그 함수 (쓰레드 이름까지 표시)
# ========================================
def log(level: str, msg: str):
    name = threading.current_thread().name
    print(f"[{level}][{name}] {msg}")


# ========================================
# TAG 파서: pk + text → category, subcategory, description, keywords, event_id
# ========================================
def parse_tag_entry(tag: dict):
    pk = tag.get("pk")
    text = tag.get("text", "")

    log("DEBUG", f"parse_tag_entry: pk={pk}, raw text='{text}'")

    if "Keywords:" not in text:
        log("ERROR", f"  TAG pk={pk} text에 'Keywords:'가 없음. 스킵.")
        return None

    head, kw_part = text.split("Keywords:", 1)
    head = head.strip()
    kw_part = kw_part.strip()

    category = ""
    subcategory = ""
    description = ""

    if " - " in head:
        left, right = head.split(" - ", 1)
        category = left.strip()
        if ":" in right:
            subcat_raw, desc_raw = right.split(":", 1)
            subcategory = subcat_raw.strip()
            description = desc_raw.strip(" .")
        else:
            subcategory = right.strip()
            description = ""
    else:
        if ":" in head:
            cat_raw, desc_raw = head.split(":", 1)
            category = cat_raw.strip()
            description = desc_raw.strip(" .")
            subcategory = ""
        else:
            category = head.strip()
            subcategory = ""
            description = ""

    keywords = [k.strip() for k in kw_part.split(",") if k.strip()]

    log("DEBUG", f"  → category='{category}', subcategory='{subcategory}'")
    log("DEBUG", f"  → description='{description}'")
    log("DEBUG", f"  → keywords={keywords}")

    return {
        "pk": pk,
        "category": category,
        "subcategory": subcategory,
        "description": description,
        "keywords": keywords,
        "event_id": tag.get("event_id") or []
    }


# ========================================
# 결과 테이블 생성 (기존 거 있으면 드롭 후 재생성)
#   └ 컬럼 5개만: id, type, lastwritetimestamp, description, tag
# ========================================
def recreate_results_table(conn):
    drop_sql = f"DROP TABLE IF EXISTS {RESULT_TABLE};"
    create_sql = f"""
    CREATE TABLE {RESULT_TABLE} (
        id                  SERIAL PRIMARY KEY,
        type                TEXT,
        lastwritetimestamp  TEXT,
        description         TEXT,
        tag                 TEXT
    );
    """
    log("DEBUG", f"DROP TABLE SQL:\n{drop_sql.strip()}")
    log("DEBUG", f"CREATE TABLE SQL:\n{create_sql.strip()}")
    try:
        with conn.cursor() as cur:
            cur.execute(drop_sql)
            cur.execute(create_sql)
            conn.commit()
        log("INFO", f"결과 테이블 '{RESULT_TABLE}' 재생성 완료 (컬럼 5개: id, type, lastwritetimestamp, description, tag)")
    except Exception as e:
        log("ERROR", f"결과 테이블 재생성 중 오류: {e}")
        traceback.print_exc()
        conn.rollback()
        raise


# ========================================
# 모든 사용자 테이블 목록 가져오기 (RESULT_TABLE 제외)
# ========================================
def get_all_user_tables(conn):
    sql = """
        SELECT schemaname, tablename
        FROM pg_catalog.pg_tables
        WHERE schemaname NOT IN ('pg_catalog', 'information_schema')
        ORDER BY schemaname, tablename;
    """
    log("DEBUG", f"테이블 목록 조회 SQL:\n{sql.strip()}")

    tables = []
    try:
        with conn.cursor(cursor_factory=DictCursor) as cur:
            cur.execute(sql)
            rows = cur.fetchall()
        for r in rows:
            schema = r["schemaname"]
            name = r["tablename"]
            if name == RESULT_TABLE:
                continue
            tables.append((schema, name))

        log("INFO", "검색 대상 테이블 목록:")
        for s, t in tables:
            log("INFO", f"  {s}.{t}")
    except Exception as e:
        log("ERROR", f"테이블 목록 조회 중 오류: {e}")
        traceback.print_exc()
        conn.rollback()

    return tables


# ========================================
# 특정 테이블의 컬럼 목록 조회
# ========================================
def get_table_columns(conn, schema: str, table: str):
    sql = """
        SELECT column_name
        FROM information_schema.columns
        WHERE table_schema = %s AND table_name = %s;
    """
    try:
        with conn.cursor() as cur:
            cur.execute(sql, (schema, table))
            rows = cur.fetchall()
        cols = [r[0] for r in rows]
        log("DEBUG", f"컬럼 조회: {schema}.{table} → {cols}")
        return cols
    except Exception as e:
        log("ERROR", f"컬럼 조회 중 오류: {schema}.{table}: {e}")
        traceback.print_exc()
        conn.rollback()
        return []


# ========================================
# 토큰 → ILIKE 패턴 ( * 처리 )
# ========================================
def token_to_ilike_pattern(token: str) -> str:
    raw = token
    token = token.strip()
    if not token:
        log("DEBUG", f"token_to_ilike_pattern: 빈 토큰 감지 (원본='{raw}') → '%' 반환")
        return "%"

    token = token.replace("*", "")
    pattern = f"%{token}%"
    log("DEBUG", f"token_to_ilike_pattern: '{raw}' → ILIKE 패턴 '{pattern}'")
    return pattern


# ========================================
# "A AND B" / "A OR B" → WHERE 절
# ========================================
def build_where_clause(keyword_pattern: str):
    pattern = keyword_pattern.strip()
    log("DEBUG", f"build_where_clause 입력 패턴: '{pattern}'")

    if not pattern:
        log("DEBUG", "빈 패턴 → WHERE TRUE")
        return "TRUE", []

    or_parts = re.split(r'\s+OR\s+', pattern, flags=re.IGNORECASE)
    log("DEBUG", f"OR 파트 분리 결과: {or_parts}")

    all_clauses = []
    all_params = []

    for idx_or, or_part in enumerate(or_parts):
        or_part_stripped = or_part.strip()
        if not or_part_stripped:
            continue

        and_tokens = re.split(r'\s+AND\s+', or_part_stripped, flags=re.IGNORECASE)
        and_tokens = [t.strip() for t in and_tokens if t.strip()]
        log("DEBUG", f"  OR 그룹 {idx_or} AND 토큰들: {and_tokens}")

        if not and_tokens:
            continue

        and_clauses = []
        and_params = []

        for token in and_tokens:
            like_pattern = token_to_ilike_pattern(token)
            and_clauses.append(f"{TEXT_COLUMN} ILIKE %s")
            and_params.append(like_pattern)

        group_clause = "(" + " AND ".join(and_clauses) + ")"
        all_clauses.append(group_clause)
        all_params.extend(and_params)

    if not all_clauses:
        log("DEBUG", "유효한 WHERE 절 없음 → TRUE")
        return "TRUE", []

    where_sql = " OR ".join(all_clauses)
    log("DEBUG", f"최종 WHERE 절: {where_sql}")
    log("DEBUG", f"최종 WHERE 파라미터: {all_params}")
    return where_sql, all_params


# ========================================
# event_id → tag 필터 (tag 컬럼 있는 테이블만)
# ========================================
def build_event_filter_clause(event_ids, has_tag_column: bool):
    if not event_ids:
        log("DEBUG", "event_id 없음 → event 필터 없음")
        return "", []

    if not has_tag_column:
        log("DEBUG", "이 테이블엔 tag 컬럼 없음 → event_id 필터 무시")
        return "", []

    placeholders = ", ".join(["%s"] * len(event_ids))
    clause = f" AND {EVENT_ID_COLUMN} IN ({placeholders})"
    params = [str(e) for e in event_ids]

    log("DEBUG", f"event_id 필터 절: {clause}")
    log("DEBUG", f"event_id 필터 파라미터: {params}")
    return clause, params


# ========================================
# TAG 하나당 쓰레드에서 실행할 worker
# ========================================
def worker_for_tag(tag: dict, tables):
    """
    각 TAG마다 별도 쓰레드에서:
      - 자기 TAG 파싱
      - 모든 테이블에 대해 INSERT ... SELECT 실행
      - 테이블 단위 commit
      - 끝나면 TAG_SUMMARY에 요약 저장
    """
    pk = tag.get("pk")
    log("INFO", f"[TAG pk={pk}] 쓰레드 시작")

    # 이 쓰레드만의 독립적인 DB 커넥션
    try:
        conn = psycopg2.connect(**DB_CONFIG)
        log("INFO", f"[TAG pk={pk}] DB 연결 성공")
    except Exception as e:
        log("ERROR", f"[TAG pk={pk}] DB 연결 실패: {e}")
        traceback.print_exc()
        return

    try:
        parsed = parse_tag_entry(tag)
        if parsed is None:
            log("ERROR", f"[TAG pk={pk}] TAG 파싱 실패, 쓰레드 종료")
            conn.close()
            return

        category = parsed["category"]
        subcategory = parsed["subcategory"]
        desc_tag = parsed["description"]
        keywords = parsed["keywords"]
        event_ids = parsed["event_id"]

        total_inserted_for_tag = 0
        matched_tables = set()

        with conn.cursor() as cur:
            for schema, table in tables:
                full_table_name = f'"{schema}"."{table}"'
                log("INFO", f"[TAG pk={pk}] 테이블 처리 시작: {schema}.{table}")

                cols = get_table_columns(conn, schema, table)
                # id, type, lastwritetimestamp, description 은 필수로 가정
                if (
                    ID_COLUMN not in cols or
                    TEXT_COLUMN not in cols or
                    TYPE_COLUMN not in cols or
                    TIME_COLUMN not in cols
                ):
                    log("WARNING", f"[TAG pk={pk}] {schema}.{table}: "
                                   f"'{ID_COLUMN}', '{TYPE_COLUMN}', '{TIME_COLUMN}', '{TEXT_COLUMN}' 중 하나 없어서 스킵.")
                    continue

                has_tag = EVENT_ID_COLUMN in cols
                if not has_tag:
                    log("DEBUG", f"[TAG pk={pk}] {schema}.{table}: '{EVENT_ID_COLUMN}' 컬럼 없음 (tag는 NULL로 저장)")

                # tag 컬럼이 없으면 NULL::TEXT로 채움
                tag_expr = EVENT_ID_COLUMN if has_tag else "NULL::TEXT"

                table_inserted = 0

                for kw_idx, kw in enumerate(keywords):
                    log("INFO", f"[TAG pk={pk}]   [KW {kw_idx}] 키워드: '{kw}'")

                    where_sql, kw_params = build_where_clause(kw)
                    ev_clause, ev_params = build_event_filter_clause(event_ids, has_tag)

                    insert_sql = f"""
                        INSERT INTO {RESULT_TABLE}
                            (type, lastwritetimestamp, description, tag)
                        SELECT
                            {TYPE_COLUMN} AS type,
                            {TIME_COLUMN}::text AS lastwritetimestamp,
                            {TEXT_COLUMN} AS description,
                            {tag_expr}   AS tag
                        FROM {full_table_name}
                        WHERE {where_sql}{ev_clause};
                    """

                    params = kw_params + ev_params

                    log("DEBUG", f"[TAG pk={pk}]   INSERT ... SELECT SQL:")
                    log("DEBUG", insert_sql.strip())
                    log("DEBUG", f"[TAG pk={pk}]   파라미터: {params}")

                    try:
                        cur.execute(insert_sql, params)
                        inserted = cur.rowcount
                        if inserted > 0:
                            matched_tables.add(f"{schema}.{table}")
                        table_inserted += inserted
                        total_inserted_for_tag += inserted
                        log("INFO", f"[TAG pk={pk}]     → INSERT된 행 수: {inserted}")
                    except Exception as e:
                        log("ERROR", f"[TAG pk={pk}]     INSERT ... SELECT 실행 중 오류 ({schema}.{table}): {e}")
                        traceback.print_exc()
                        conn.rollback()
                        continue

                # 이 테이블에 대한 작업이 끝났으면 commit
                try:
                    conn.commit()
                    log("INFO", f"[TAG pk={pk}]   {schema}.{table} 커밋 완료 (삽입 {table_inserted} 행)")
                except Exception as e:
                    log("ERROR", f"[TAG pk={pk}]   {schema}.{table} 커밋 중 오류: {e}")
                    traceback.print_exc()
                    conn.rollback()

        log("INFO", f"[TAG pk={pk}] 쓰레드 종료, 총 삽입 {total_inserted_for_tag} 행")

        # TAG별 요약 정보 전역 변수에 저장
        with SUMMARY_LOCK:
            TAG_SUMMARY[pk] = {
                "category": category,
                "subcategory": subcategory,
                "description": desc_tag,
                "keywords": keywords,
                "event_ids": event_ids,
                "total_inserted": total_inserted_for_tag,
                "tables": sorted(matched_tables),
            }

    except Exception as e:
        log("ERROR", f"[TAG pk={pk}] worker 내부 예외: {e}")
        traceback.print_exc()
    finally:
        try:
            conn.close()
            log("INFO", f"[TAG pk={pk}] DB 연결 종료")
        except Exception:
            pass


# ========================================
# 결과 테이블 요약 (5컬럼 기반)
# ========================================
def print_results_summary():
    try:
        conn = psycopg2.connect(**DB_CONFIG)
    except Exception as e:
        log("ERROR", f"요약 조회용 DB 연결 실패: {e}")
        traceback.print_exc()
        return

    try:
        with conn.cursor(cursor_factory=DictCursor) as cur:
            # 전체 개수
            cur.execute(f"SELECT COUNT(*) AS cnt FROM {RESULT_TABLE};")
            cnt = cur.fetchone()["cnt"]
            log("INFO", f"결과 테이블 '{RESULT_TABLE}' 총 행 수: {cnt}")

            # 최근 20개만, 5개 컬럼 기반
            cur.execute(f"""
                SELECT
                    id,
                    type,
                    lastwritetimestamp,
                    description,
                    tag
                FROM {RESULT_TABLE}
                ORDER BY id DESC
                LIMIT 20;
            """)
            rows = cur.fetchall()

            log("INFO", "최근 20개 결과 (id / type / time / tag / desc):")
            for r in rows:
                log("INFO",
                    f"  [id={r['id']}] type='{r['type']}' "
                    f"| time='{r['lastwritetimestamp']}' "
                    f"| tag='{r['tag']}'"
                )
                log("INFO", f"    desc='{r['description']}'")

    except Exception as e:
        log("ERROR", f"결과 요약 조회 중 오류: {e}")
        traceback.print_exc()
        conn.rollback()
    finally:
        conn.close()


# ========================================
# TAG별 어디서 찾았는지 요약 출력 (메모리상 정보)
# ========================================
def print_tag_summary():
    log("INFO", "=== TAG별 매칭 요약 (어디서 찾았는지) ===")
    with SUMMARY_LOCK:
        if not TAG_SUMMARY:
            log("INFO", "TAG_SUMMARY 비어 있음 (매칭 결과 없음)")
            return

        for pk, info in TAG_SUMMARY.items():
            log("INFO", f"[TAG pk={pk}] {info['category']} - {info['subcategory']}")
            log("INFO", f"  설명: {info['description']}")
            log("INFO", f"  사용 키워드: {', '.join(info['keywords'])}")
            if info["event_ids"]:
                log("INFO", f"  event_id 필터: {info['event_ids']}")
            log("INFO", f"  총 삽입 행 수: {info['total_inserted']}")
            if info["tables"]:
                log("INFO", "  매칭된 테이블 목록:")
                for t in info["tables"]:
                    log("INFO", f"    - {t}")
            else:
                log("INFO", "  매칭된 테이블 없음")


# ========================================
# main
# ========================================
def main():
    log("INFO", f"DB 접속 설정: {DB_CONFIG}")
    log("INFO", f"결과 테이블: {RESULT_TABLE}")
    log("INFO", f"공통 컬럼: ID_COLUMN='{ID_COLUMN}', TYPE_COLUMN='{TYPE_COLUMN}', "
               f"TIME_COLUMN='{TIME_COLUMN}', TEXT_COLUMN='{TEXT_COLUMN}', EVENT_ID_COLUMN='{EVENT_ID_COLUMN}'")

    # 준비용 메인 커넥션 (테이블 생성 + 목록 조회)
    try:
        conn_main = psycopg2.connect(**DB_CONFIG)
    except Exception as e:
        log("ERROR", f"준비용 DB 연결 실패: {e}")
        traceback.print_exc()
        return

    log("INFO", "준비용 DB 연결 성공")

    try:
        # 1) 결과 테이블 구조 재생성 (컬럼 5개)
        recreate_results_table(conn_main)

        # 2) 검색 대상 테이블 목록 가져오기
        tables = get_all_user_tables(conn_main)

    except Exception as e:
        log("ERROR", f"main 준비 단계 예외: {e}")
        traceback.print_exc()
        conn_main.close()
        return
    finally:
        try:
            conn_main.close()
            log("INFO", "준비용 DB 연결 종료")
        except Exception:
            pass

    # 3) TAG별로 쓰레드 생성 및 실행
    threads = []
    for tag in TAGS:
        pk = tag.get("pk")
        t = threading.Thread(
            target=worker_for_tag,
            args=(tag, tables),
            name=f"Tag-{pk}"
        )
        threads.append(t)
        t.start()
        log("INFO", f"[TAG pk={pk}] 쓰레드 시작 요청")

    # 4) 모든 쓰레드 종료 기다리기
    for t in threads:
        t.join()
        log("INFO", f"{t.name} join 완료")

    # 5) 결과 요약 출력 (5컬럼 위주)
    print_results_summary()

    # 6) TAG별 어디서 찾았는지 요약 출력 (메모리)
    print_tag_summary()


if __name__ == "__main__":
    main()
