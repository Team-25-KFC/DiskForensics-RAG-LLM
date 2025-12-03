# -*- coding: utf-8 -*-
r"""
D:\ccit\tagged 경로들(D:~Z:) 아래 있는 CSV 파일들을
PostgreSQL forensic_db.artifact_all 테이블에 넣는 스크립트.

CSV 헤더:
    Type, LastWriteTimestamp, description, tag

DB 테이블 스키마(최소 요건):
    CREATE TABLE IF NOT EXISTS artifact_all (
        id SERIAL PRIMARY KEY,
        type TEXT,
        lastwritetimestamp TEXT,
        description TEXT,
        tag TEXT
    );
"""

import os
import glob
import csv
import psycopg2
from psycopg2.extras import execute_batch

# =========================
# 0. DB 설정
# =========================

DB_INFO = dict(
    host="localhost",
    dbname="forensic_db",
    user="postgres",
    password="admin123",
)

# =========================
# 1. 경로 탐색
# =========================

def find_tagged_dirs() -> list:
    """
    D: ~ Z: 드라이브를 순회하면서
    '<드라이브>:\\ccit\\tagged' 폴더가 존재하는지 확인하고,
    존재하면 그 경로를 리스트에 담아 반환.
    """
    candidates = []
    for drive_letter in range(ord('D'), ord('Z') + 1):
        drive = f"{chr(drive_letter)}:\\"
        base_dir = os.path.join(drive, "ccit", "tagged")
        if os.path.isdir(base_dir):
            candidates.append(base_dir)
    return candidates


def iter_csv_files(tagged_dir: str):
    """
    주어진 tagged_dir 아래에 있는 모든 .csv 파일을 찾는다.
    (현재는 서브디렉토리는 보지 않고, 루트만)
    """
    pattern = os.path.join(tagged_dir, "*.csv")
    for path in glob.glob(pattern):
        yield path

# =========================
# 2. DB 접속 & 테이블 준비/초기화
# =========================

def get_connection():
    conn = psycopg2.connect(**DB_INFO)
    conn.autocommit = False
    return conn


def reset_artifact_all(conn):
    """
    artifact_all 테이블이 없으면 만들고,
    매 실행마다 내용을 TRUNCATE로 싹 비운다.
    """
    create_sql = """
    CREATE TABLE IF NOT EXISTS artifact_all (
        id SERIAL PRIMARY KEY,
        type TEXT,
        lastwritetimestamp TEXT,
        description TEXT,
        tag TEXT
    );
    """
    with conn.cursor() as cur:
        cur.execute(create_sql)
        cur.execute("TRUNCATE TABLE artifact_all;")
    conn.commit()
    print("[INFO] artifact_all table has been reset (TRUNCATE).")

# =========================
# 3. CSV → artifact_all 적재
# =========================

def load_csv_to_artifact_all(conn, csv_path: str):
    print(f"[INFO] Loading CSV -> artifact_all: {csv_path}")

    rows_to_insert = []

    with open(csv_path, "r", encoding="utf-8-sig", newline="") as f:
        reader = csv.DictReader(f)
        fieldnames = [name.strip() for name in reader.fieldnames or []]

        # 대소문자/공백 방어용 매핑
        # 예: Description / description / DESCRIPTION 다 받게
        def get_field(row, *candidates):
            for key in candidates:
                if key in row and row[key] is not None:
                    return row[key]
            return ""

        for line_no, row in enumerate(reader, start=2):
            try:
                # DictReader는 원래 헤더 그대로 키로 쓰니까, strip 한 버전도 같이 사용
                # row 키를 통째로 소문자화한 dict를 만들어도 됨
                norm_row = {k.strip(): v for k, v in row.items()}

                type_val = (get_field(norm_row, "Type", "type") or "").strip()
                ts_val   = (get_field(norm_row, "LastWriteTimestamp", "lastwritetimestamp") or "").strip()
                desc_val = (get_field(norm_row, "description", "Description", "desc") or "").strip()
                tag_val  = (get_field(norm_row, "tag", "Tag", "tags", "Tags") or "").strip()

                rows_to_insert.append(
                    (type_val, ts_val, desc_val, tag_val)
                )
            except Exception as e:
                print(f"[WARN] {csv_path} line {line_no}: {e}")


    if not rows_to_insert:
        print(f"[INFO] No valid rows found in {csv_path}. Skipping.")
        return

    insert_sql = """
    INSERT INTO artifact_all (type, lastwritetimestamp, description, tag)
    VALUES (%s, %s, %s, %s);
    """

    with conn.cursor() as cur:
        execute_batch(cur, insert_sql, rows_to_insert, page_size=1000)
    conn.commit()

    print(f"[INFO] Inserted {len(rows_to_insert)} rows from {csv_path}.")

# =========================
# 4. 메인 플로우
# =========================

def main():
    print("[INFO] Searching for tagged directories (D:~Z:) ...")
    tagged_dirs = find_tagged_dirs()

    if not tagged_dirs:
        print("[WARN] No 'ccit/tagged' directories found in drives D:~Z:.")
        return

    print("[INFO] Found tagged dirs:")
    for d in tagged_dirs:
        print(f"  - {d}")

    conn = get_connection()
    try:
        # 테이블 생성 + 내용 초기화
        reset_artifact_all(conn)

        for tagged_dir in tagged_dirs:
            print(f"[INFO] Scanning CSV files in {tagged_dir} ...")
            for csv_path in iter_csv_files(tagged_dir):
                load_csv_to_artifact_all(conn, csv_path)

        print("[INFO] All CSV files have been processed.")
    finally:
        conn.close()
        print("[INFO] DB connection closed.")


if __name__ == "__main__":
    main()
