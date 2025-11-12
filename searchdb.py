#!/usr/bin/env python3
# -*- coding: utf-8 -*-

import os
import re
import json
import argparse
import itertools
from typing import List, Dict, Any, Tuple

import psycopg2
from psycopg2.extras import RealDictCursor
import requests

from pymilvus import connections, Collection, FieldSchema, CollectionSchema, DataType, utility


# =========================
# Config (환경변수/기본값)
# =========================
PG_HOST = os.getenv("PG_HOST", "localhost")
PG_PORT = int(os.getenv("PG_PORT", "5432"))
PG_DB   = os.getenv("PG_DB", "rudrb")
PG_USER = os.getenv("PG_USER", "rudrb")
PG_PASS = os.getenv("PG_PASS", "rudrb123")

LMSTUDIO_EMBED_URL = os.getenv("LMSTUDIO_EMBED_URL", "http://localhost:1234/v1/embeddings")
LMSTUDIO_EMBED_MODEL = os.getenv("LMSTUDIO_EMBED_MODEL", "text-embedding-sentence-transformers_all-minilm-l12-v2")

MILVUS_HOST = os.getenv("MILVUS_HOST", "localhost")
MILVUS_PORT = os.getenv("MILVUS_PORT", "19530")
MILVUS_COLLECTION = os.getenv("MILVUS_COLLECTION", "tag_test")
EMBED_DIM = int(os.getenv("EMBED_DIM", "384"))

# 검색 대상 테이블 패턴 (필요 시 수정)
TABLE_NAME_FILTER_SQL = """
    SELECT table_name
    FROM information_schema.tables
    WHERE table_schema='public'
      AND (
          table_name LIKE '%_Output_tagged'
          OR table_name LIKE '%_Output'
          OR table_name LIKE '%_ASEPs_Output%'
          OR table_name LIKE '%_UserActivity_Output%'
          OR table_name LIKE 'view_%'
      )
    ORDER BY table_name;
"""


# =========================
# 유틸
# =========================
def load_json_file(path: str) -> Any:
    with open(path, "r", encoding="utf-8") as f:
        return json.load(f)

def find_json_blocks(text: str) -> List[Dict[str, Any]]:
    """
    메시지 안의 ```json ... ``` 블록에서 JSON 객체들을 추출.
    메시지가 아니라 파일이라면 이 함수는 사용 안 해도 됨.
    """
    blocks = re.findall(r"```json\s*(\{.*?\})\s*```", text, re.DOTALL)
    out = []
    for b in blocks:
        try:
            out.append(json.loads(b))
        except Exception:
            pass
    return out

def expand_placeholders(s: str, mapping: Dict[str, List[str]]) -> List[str]:
    """
    문자열 s 내의 플레이스홀더(<USER>, <GUID> 등)를 mapping의 모든 값 조합으로 확장.
    매핑이 하나도 없으면 [s] 그대로 반환.
    """
    placeholders_in_s = [ph for ph in mapping.keys() if ph in s]
    if not placeholders_in_s:
        return [s]

    # 순서 고정: 문자열에 등장한 순서
    seq = []
    for ph in placeholders_in_s:
        seq.append((ph, mapping[ph]))

    # product로 모든 조합 생성
    all_versions = set()
    def apply_combo(base: str, combo_pairs: List[Tuple[str, str]]) -> str:
        out = base
        for ph, val in combo_pairs:
            out = out.replace(ph, val)
        return out

    keys = [k for k, _ in seq]
    vals = [v for _, v in seq]
    for combo in itertools.product(*vals):
        combo_pairs = list(zip(keys, combo))
        all_versions.add(apply_combo(s, combo_pairs))

    return list(all_versions)

def glob_to_ilike_pieces(pattern: str) -> List[str]:
    """
    "C:\\Windows\\System32\\Tasks\\*" 같은 글롭을 ILIKE 조건 2개로 분해.
    head*tail -> [head%, %tail]
    '*'가 없다면 패턴 그대로 한 덩어리 반환.
    백슬래시는 SQL 문자열용으로 한 번 더 이스케이프.
    """
    if "*" not in pattern:
        return [pattern.replace("\\", "\\\\")]
    head, tail = pattern.split("*", 1)
    head_sql = head.replace("\\", "\\\\") + "%"
    tail_sql = "%" + tail.replace("\\", "\\\\")
    return [head_sql, tail_sql]

def build_concat_expr(columns: List[str]) -> str:
    """
    검색에 사용할 가변 컬럼들의 문자열 결합 표현식 생성.
    COALESCE로 NULL 안전하게.
    """
    cols_set = set(columns)
    if {"type", "description"}.issubset(cols_set):
        return "COALESCE(type,'') || ' ' || COALESCE(description,'')"
    if {"keypath", "value", "data"}.issubset(cols_set):
        return "COALESCE(keypath,'') || ' ' || COALESCE(value,'') || ' ' || COALESCE(data,'')"
    usable = [c for c in columns if c not in ("id",)]
    if not usable:
        return "''"
    return " || ' ' || ".join([f"COALESCE({c},'')" for c in usable])

def build_where_and_params(concat_expr: str, keyword: str) -> Tuple[str, List[str]]:
    """
    키워드 한 줄을 받아서 (AND/OR 지원, * 글롭 지원) WHERE절과 파라미터 리스트 생성.
    """
    # 먼저 글롭(*)이 있는 경우는 ILIKE 두 조각으로 분해해서 AND로 붙인다.
    def pieces_for_token(token: str) -> List[str]:
        token = token.strip()
        if "*" in token:
            return glob_to_ilike_pieces(token)
        return [token.replace("\\", "\\\\")]

    params = []
    if " AND " in keyword:
        parts = [p.strip() for p in keyword.split("AND") if p.strip()]
        conds = []
        for p in parts:
            pcs = pieces_for_token(p)
            if len(pcs) == 2:
                # head% AND %tail
                conds.append(f"({concat_expr} ILIKE %s AND {concat_expr} ILIKE %s)")
                params.extend(pcs)
            else:
                conds.append(f"({concat_expr} ILIKE %s)")
                params.append(f"%{pcs[0]}%")
        where = " AND ".join(conds)
        return where, params

    if " OR " in keyword:
        parts = [p.strip() for p in keyword.split("OR") if p.strip()]
        conds = []
        for p in parts:
            pcs = pieces_for_token(p)
            if len(pcs) == 2:
                conds.append(f"(({concat_expr} ILIKE %s AND {concat_expr} ILIKE %s))")
                params.extend(pcs)
            else:
                conds.append(f"({concat_expr} ILIKE %s)")
                params.append(f"%{pcs[0]}%")
        where = " OR ".join(conds)
        return where, params

    # 단일 키워드
    pcs = pieces_for_token(keyword)
    if len(pcs) == 2:
        where = f"({concat_expr} ILIKE %s AND {concat_expr} ILIKE %s)"
        params.extend(pcs)
    else:
        where = f"{concat_expr} ILIKE %s"
        params.append(f"%{pcs[0]}%")
    return where, params


# =========================
# 메인 로직
# =========================
def main():
    ap = argparse.ArgumentParser(description="Tag JSON → PostgreSQL match → Milvus upload (with <USER>/<GUID> expansion).")
    ap.add_argument("--tags", required=True, help="태그 JSON 파일 경로 (단일 오브젝트 또는 리스트).")
    ap.add_argument("--user-guid", required=True, help="user_guid.json 경로 (mapping: { '<USER>': [...], '<GUID>': [...] }).")
    ap.add_argument("--recreate", action="store_true", help="Milvus 컬렉션을 삭제 후 재생성.")
    ap.add_argument("--dry-run", action="store_true", help="DB/임베딩/업로드 없이 쿼리와 카운트만 확인.")
    args = ap.parse_args()

    # --- 로드 ---
    tags_obj = load_json_file(args.tags)
    mapping_obj = load_json_file(args.user_guid)
    mapping = mapping_obj.get("mapping", {})

    # 태그를 리스트로 통일
    if isinstance(tags_obj, dict):
        tags = [tags_obj]
    elif isinstance(tags_obj, list):
        tags = tags_obj
    else:
        raise ValueError("tags JSON은 객체 또는 배열이어야 합니다.")

    # --- Postgres 연결 ---
    conn = psycopg2.connect(
        host=PG_HOST, port=PG_PORT, dbname=PG_DB, user=PG_USER, password=PG_PASS
    )
    cur = conn.cursor()
    cur_dict = conn.cursor(cursor_factory=RealDictCursor)

    # 테이블 목록
    cur.execute(TABLE_NAME_FILTER_SQL)
    tables = [t[0] for t in cur.fetchall()]
    print(f"[i] 대상 테이블 {len(tables)}개: {', '.join(tables)}")

    matched_rows = []
    total_hits = 0

    # --- 태그 처리 ---
    for tag in tags:
        # 1) keywords 찾기
        keywords: List[str] = []
        if "keywords" in tag and isinstance(tag["keywords"], list):
            keywords = [str(k) for k in tag["keywords"]]
        # (옵션) description/text에 'Keywords:' 구문이 있으면 파싱
        elif "text" in tag and isinstance(tag["text"], str) and "Keywords:" in tag["text"]:
            part = tag["text"].split("Keywords:", 1)[-1]
            keywords = [k.strip() for k in part.split(",") if k.strip()]

        print(f"\n[Tag] {tag.get('subcategory','(no-subcat)')} — keywords: {len(keywords)}")

        for kw in keywords:
            # 백슬래시 이스케이프는 파라미터 바인딩으로 안전 처리하므로 여기선 원문 유지
            # 플레이스홀더 확장
            expanded_list = expand_placeholders(kw, mapping)

            for kw_expanded in expanded_list:
                for table_name in tables:
                    # 열 목록
                    cur.execute("""
                        SELECT column_name
                        FROM information_schema.columns
                        WHERE table_schema='public' AND table_name=%s;
                    """, (table_name,))
                    columns = [r[0] for r in cur.fetchall()]
                    if not columns:
                        continue

                    concat_expr = build_concat_expr(columns)
                    where, params = build_where_and_params(concat_expr, kw_expanded)
                    query = f'SELECT * FROM "{table_name}" WHERE {where};'

                    if args.dry_run:
                        print(f"   - DRY SQL [{table_name}]: {query}  | params={params}")
                        continue

                    try:
                        cur_dict.execute(query, params)
                        rows = cur_dict.fetchall()
                        hit = len(rows)
                        if hit:
                            total_hits += hit
                            for r in rows:
                                matched_rows.append((table_name, kw_expanded, r))
                            print(f"   ✓ [{table_name}] '{kw_expanded}' → {hit} rows")
                        else:
                            print(f"   · [{table_name}] '{kw_expanded}' → 0")
                    except Exception as e:
                        print(f"   ! SQL 오류 ({table_name}, '{kw_expanded}'): {e}")
                        conn.rollback()

    if args.dry_run:
        print("\n[DRY-RUN] 종료 — 쿼리만 점검했습니다.")
        return

    print(f"\n[i] 매칭 총 행 수: {total_hits}")

    # --- Milvus 연결/컬렉션 ---
    print(f"[i] Milvus 연결: {MILVUS_HOST}:{MILVUS_PORT} / collection={MILVUS_COLLECTION}")
    connections.connect("default", host=MILVUS_HOST, port=MILVUS_PORT)

    if args.recreate and utility.has_collection(MILVUS_COLLECTION):
        utility.drop_collection(MILVUS_COLLECTION)
        print(f"[i] 기존 컬렉션 '{MILVUS_COLLECTION}' 삭제")

    if not utility.has_collection(MILVUS_COLLECTION):
        fields = [
            FieldSchema(name="id", dtype=DataType.INT64, is_primary=True, auto_id=True),
            FieldSchema(name="text", dtype=DataType.VARCHAR, max_length=2000),
            FieldSchema(name="vector", dtype=DataType.FLOAT_VECTOR, dim=EMBED_DIM),
        ]
        schema = CollectionSchema(fields, description="Forensic keyword match results")
        collection = Collection(MILVUS_COLLECTION, schema)
        print(f"[i] 새 컬렉션 '{MILVUS_COLLECTION}' 생성")
    else:
        collection = Collection(MILVUS_COLLECTION)

    # --- 임베딩 입력 준비 ---
    texts = []
    for table_name, kw_used, row_dict in matched_rows:
        # id 등 불필요 필드 제거 가능
        row_copy = dict(row_dict)
        row_copy.pop("id", None)
        row_copy.pop("tag", None)
        json_text = json.dumps(row_copy, ensure_ascii=False)
        texts.append(json_text)

    # 중복 제거
    texts = list(dict.fromkeys(texts))
    print(f"[i] 임베딩 대상 텍스트: {len(texts)}개")

    if not texts:
        print("[i] 업로드할 데이터가 없습니다. 종료.")
        return

    # --- LM Studio 임베딩 요청 ---
    print(f"[i] LM Studio 임베딩 요청 → {LMSTUDIO_EMBED_URL} (model={LMSTUDIO_EMBED_MODEL})")
    r = requests.post(
        LMSTUDIO_EMBED_URL,
        json={"model": LMSTUDIO_EMBED_MODEL, "input": texts},
        timeout=120
    )
    if r.status_code != 200:
        raise RuntimeError(f"LM Studio 요청 실패: {r.status_code} {r.text}")

    data = r.json()
    embeddings = [item["embedding"] for item in data.get("data", [])]
    if len(embeddings) != len(texts):
        raise ValueError("임베딩 개수와 텍스트 개수가 일치하지 않습니다.")

    # --- Milvus 삽입 & 인덱스 ---
    print("[i] Milvus insert…")
    collection.insert([texts, embeddings])
    collection.flush()

    # 인덱스가 없다면 생성(여러 번 호출해도 안전)
    try:
        collection.create_index(
            field_name="vector",
            index_params={"index_type": "IVF_FLAT", "metric_type": "COSINE", "params": {"nlist": 1024}}
        )
        print("[i] Milvus 인덱스 생성 완료")
    except Exception as e:
        print(f"[!] 인덱스 생성 스킵 또는 오류: {e}")

    print("\n✅ 완료 — 매칭행: {}, 업로드: {}개".format(total_hits, len(texts)))


if __name__ == "__main__":
    main()
