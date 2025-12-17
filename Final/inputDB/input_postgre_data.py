# -*- coding: utf-8 -*-
r"""
D:\tagged 경로들(D:~Z:) 아래 있는 CSV 파일들을
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

CSV 적재가 모두 끝난 뒤,
localhost에 간단한 HTTP 서버를 열고 한 번의 요청을 기다린다.
LangFlow는 이 서버에 주기적으로 요청을 보내고,
200 OK 응답을 받으면 다음 노드로 넘어가도록 구성한다.
"""

import os
import glob
import csv
import psycopg2
from psycopg2.extras import execute_batch

from http.server import HTTPServer, BaseHTTPRequestHandler  # ★ 추가

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
    '<드라이브>:\\tagged' 폴더가 존재하는지 확인하고,
    존재하면 그 경로를 리스트에 담아 반환.
    """
    candidates = []
    for drive_letter in range(ord('D'), ord('Z') + 1):
        drive = f"{chr(drive_letter)}:\\"
        base_dir = os.path.join(drive, "tagged")
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

        # 헤더가 없으면 스킵
        if not reader.fieldnames:
            print(f"[WARN] {csv_path}: fieldnames is None. Skipping.")
            return

        # 대소문자/공백 방어용 get_field
        def get_field(row: dict, *candidates) -> str:
            """
            row에서 candidates 중 하나에 해당하는 키가 있으면 그 값을 반환.
            키 이름은 그대로 비교하되, row는 norm_row(공백 제거) 기준으로 사용.
            """
            for key in candidates:
                if key in row and row[key] is not None:
                    return row[key]
            return ""

        for line_no, row in enumerate(reader, start=2):
            try:
                # DictReader는 원래 헤더 그대로 키로 쓰니까, strip 한 버전도 같이 사용
                norm_row = { (k or "").strip(): v for k, v in row.items() }

                type_val = (get_field(norm_row, "Type", "type") or "").strip()

                # ✅ LastWriteTimestamp / LastWriteTimestemp / time 등 여러 케이스 방어
                ts_val = (
                    get_field(
                        norm_row,
                        "LastWriteTimestamp",   # 정식
                        "lastwritetimestamp",   # 소문자
                        "LastWriteTimestemp",   # 오타(대문자)
                        "lastwritetimestemp",   # 오타(소문자)
                        "time",                 # 다른 도구에서 time 으로만 뽑힌 경우
                    ) or ""
                ).strip()

                # ✅ description / desc / descrition 등 다양한 케이스 방어
                desc_val = (
                    get_field(
                        norm_row,
                        "description",   # 정식(소문자)
                        "Description",   # 정식(대문자)
                        "desc", "Desc",  # 축약형
                        "descrition",    # 오타
                        "Descrition",    # 오타(대문자)
                    ) or ""
                ).strip()

                tag_val = (
                    get_field(
                        norm_row,
                        "tag", "Tag",   # 기본
                        "tags", "Tags"  # 복수형
                    ) or ""
                ).strip()

                rows_to_insert.append(
                    (type_val, ts_val, desc_val, tag_val)
                )

            except Exception as e:
                # 한 줄에서 뭔가 터져도 전체 로드는 계속 진행
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
# 4. 완료 신호용 HTTP 서버
# =========================

class ReadyHandler(BaseHTTPRequestHandler):
    """
    LangFlow가 /ready 엔드포인트로 GET을 보내면
    200 OK와 간단한 메시지를 반환하고, 서버는 한 요청을 처리한 후 종료하게 된다.
    """

    # 로깅 죽이기 (콘솔에 시끄럽게 안 찍히게)
    def log_message(self, format, *args):
        return

    def do_GET(self):
        if self.path == "/ready":
            body = b"READY"
            self.send_response(200)
            self.send_header("Content-Type", "text/plain; charset=utf-8")
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            self.wfile.write(body)
        else:
            self.send_response(404)
            self.end_headers()


def start_ready_server_once(host: str = "127.0.0.1", port: int = 8002):
    """
    /ready 엔드포인트를 한 번 처리하고 종료하는 단발성 HTTP 서버.
    - handle_request()는 딱 한 번 요청을 처리하면 반환한다.
    - LangFlow 쪽에서 이 포트로 GET /ready를 보내면,
      이 함수가 반환되고, 그 뒤에 이 스크립트도 종료된다.

    ※ 아직 요청이 안 들어왔으면, 여기서 블록된 상태로 대기한다.
    """
    server_address = (host, port)
    httpd = HTTPServer(server_address, ReadyHandler)
    print(f"[INFO] Ready server started at http://{host}:{port}/ready (waiting for a single request)...")
    try:
        # 하나의 요청을 처리할 때까지 블록
        httpd.handle_request()
        print("[INFO] Ready server handled one request and is shutting down.")
    except Exception as e:
        print(f"[WARN] Ready server error: {e}")
    finally:
        httpd.server_close()

# =========================
# 5. 메인 플로우
# =========================

def main():
    print("[INFO] Searching for tagged directories (D:~Z:) ...")
    tagged_dirs = find_tagged_dirs()

    if not tagged_dirs:
        print("[WARN] No 'tagged' directories found in drives D:~Z:.")
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

    # CSV 적재가 다 끝난 뒤 LangFlow에게 "준비 완료" 신호
    start_ready_server_once(host="127.0.0.1", port=8002)


if __name__ == "__main__":
    main()
