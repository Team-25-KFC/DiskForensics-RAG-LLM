#!/usr/bin/env python3
# multi_view_correlation_textdate.py
# created_date 컬럼이 없는 DB에서도 정상 작동하는 버전

import sys
import re
from datetime import datetime
from typing import List, Dict, Tuple
import psycopg2
import pandas as pd

# ====== DB 연결 정보 ======
DB_INFO = dict(
    dbname="forensic_db",
    user="postgres",
    password="admin123",
    host="localhost",
    port="5432"
)

# ====== 뷰 매핑 ======
VIEW_MAP = {
    "System": "view_system",
    "Execution": "view_execution",
    "Exfiltration": "view_exfiltration",
    "UserActivity": "view_useractivity"
}

# ====== 태그별 키워드 ======
TAG_RULES = {
    "Execution": ["powershell", "cmd", "exe", "script", "payload"],
    "Exfiltration": ["dns", "http", "upload", "transfer", "exfil", "indexeddb"],
    "System": ["login", "logon", "registry", "product id", "hostname", "service", "os"],
    "UserActivity": ["usb", "recent", "mru", "browser", "indexdb"]
}

BASE_KEYWORDS = {
    "Execution": ["powershell", "cmd", "rundll", "script", "exe"],
    "Exfiltration": ["http", "upload", "dns", "indexeddb", "httpapi"],
    "System": ["os", "version", "registry", "product id", "hostname", "logon"],
    "UserActivity": ["usb", "recent", "mru", "browser"]
}

# ====== 태그 추론 ======
def infer_tags_from_question(question: str) -> List[str]:
    q = question.lower()
    matches = set()
    for tag, kws in TAG_RULES.items():
        for kw in kws:
            if kw in q:
                matches.add(tag)
    return list(matches) if matches else list(VIEW_MAP.keys())

# ====== SQL 빌더 (created_date 없는 버전) ======
def build_sql_for_view(view_name: str, tag_pattern: str, include_keywords: List[str], date_str: str = None, limit: int = 200) -> Tuple[str, List]:
    """
    created_date 없는 버전: full_description 내부 LIKE 검색 기반
    """
    where_clauses = []
    params = []

    # tag 필터
    where_clauses.append("tag ILIKE %s")
    params.append(f"%{tag_pattern}%")

    # 키워드 검색 (OR)
    if include_keywords:
        inc = " OR ".join(["full_description ILIKE %s"] * len(include_keywords))
        where_clauses.append(f"({inc})")
        params += [f"%{kw}%" for kw in include_keywords]

    # 날짜 검색 (문자열 LIKE)
    if date_str:
        where_clauses.append("(full_description ILIKE %s)")
        params.append(f"%{date_str}%")

    where_sql = " AND ".join(where_clauses) if where_clauses else "TRUE"
    sql = f"""
    SELECT id, source, artifact_name, file_name,
           LEFT(full_description, 400) AS preview,
           tag
    FROM {view_name}
    WHERE {where_sql}
    ORDER BY id DESC
    LIMIT {limit};
    """
    return sql, params

# ====== DB 실행 ======
def query_db(sql: str, params: List) -> pd.DataFrame:
    conn = psycopg2.connect(**DB_INFO)
    try:
        df = pd.read_sql_query(sql, conn, params=params)
    finally:
        conn.close()
    return df

# ====== 다중 뷰 검색 + 병합 ======
def multi_view_search(question: str, date_str: str = None, limit_per_view: int = 200):
    tags = infer_tags_from_question(question)
    print(f"[INFO] 추론된 태그: {tags}")

    merged_results = []
    for tag in tags:
        view = VIEW_MAP.get(tag)
        if not view:
            continue

        # 키워드 구성
        includes = BASE_KEYWORDS.get(tag, [])[:]
        tokens = re.findall(r"[a-zA-Z0-9_@.-]{3,}", question.lower())
        for t in tokens:
            if t not in includes and len(includes) < 12:
                includes.append(t)

        sql, params = build_sql_for_view(view, tag, includes, date_str=date_str, limit=limit_per_view)
        try:
            df = query_db(sql, params)
        except Exception as e:
            print(f"[WARN] 뷰 {view} 조회 실패: {e}")
            continue
        if not df.empty:
            df["view"] = view
            df["tag_inferred"] = tag
            merged_results.append(df)

    if not merged_results:
        print("검색 결과 없음.")
        return pd.DataFrame()

    merged_df = pd.concat(merged_results, ignore_index=True)
    merged_df.drop_duplicates(subset=["view", "id"], inplace=True)

    print("\n===== 검색 결과 (상위 30행) =====")
    print(merged_df.head(30).to_string(index=False))
    print(f"\n총 {len(merged_df)}개 결과.")
    return merged_df

# ====== CLI 실행 ======
if __name__ == "__main__":
    if len(sys.argv) >= 2:
        question = sys.argv[1]
        date_str = sys.argv[2] if len(sys.argv) >= 3 else None
    else:
        question = input("질문 (예: 2025-10-10 공격 있었어?):\n> ")
        date_str = input("날짜 (YYYY-MM-DD, 생략 가능):\n> ").strip() or None

    multi_view_search(question, date_str)
