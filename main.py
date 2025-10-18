<<<<<<< HEAD
import os, json, csv, shutil
from typing import List, Dict, Any, Optional
from mcp.server.fastmcp import FastMCP

mcp = FastMCP("forensic-mcp-server")


# 작업공간(샌드박스) 설정

WORKSPACE_DIR = os.path.abspath("../")   #경로 설정 지금은 ccitmcp
os.makedirs(WORKSPACE_DIR, exist_ok=True)

def _resolve_in_workspace(rel_path: str) -> str:
    """Change the relative path based on mcp-server to the absolute path, and an exception occurs when leaving"""
    rel_path = rel_path or "."
    target = os.path.abspath(os.path.join(WORKSPACE_DIR, rel_path))
    if os.path.commonpath([WORKSPACE_DIR, target]) != WORKSPACE_DIR:
        raise ValueError("Access denied: Path escapes workspace.")
    return target

def _ensure_parent_dir(path_abs: str):
    parent = os.path.dirname(path_abs) or WORKSPACE_DIR
    os.makedirs(parent, exist_ok=True)


# 유틸리티 툴

@mcp.tool()
def list_files(directory: str = ".") -> List[str]:
    """List of directories based on workspace ('.../')"""
    try:
        target = _resolve_in_workspace(directory)
        if not os.path.exists(target):
            return [f"Error: Directory '{directory}' not found."]
        if not os.path.isdir(target):
            return [f"Error: '{directory}' is not a directory."]
        return os.listdir(target)
    except Exception as e:
        return [f"An error occurred: {e}"]

@mcp.tool()
def make_dir(directory: str) -> str:
    """Create workspace reference directory (it's OK to exist)"""
    try:
        target = _resolve_in_workspace(directory)
        os.makedirs(target, exist_ok=True)
        return f"Directory ensured: '{directory}'."
    except Exception as e:
        return f"An error occurred: {e}"

@mcp.tool()
def read_file(filepath: str, encoding: str = "utf-8") -> str:
    """Read workspace reference file (director error)"""
    try:
        target = _resolve_in_workspace(filepath)
        if not os.path.exists(target):
            return f"Error: File '{filepath}' not found."
        if os.path.isdir(target):
            return f"Error: '{filepath}' is a directory, not a file."
        with open(target, "r", encoding=encoding) as f:
            return f.read()
    except Exception as e:
        return f"An error occurred: {e}"

@mcp.tool()
def write_file(filepath: str, content: str, encoding: str = "utf-8") -> str:
    """Write workspace reference file (overwrite). Reject directory path."""
    try:
        # 디렉터리로 끝나는 문자열 사전 차단
        if filepath.endswith(("/", "\\", os.path.sep)):
            return f"Error: '{filepath}' is a directory. Provide a file name."
        target = _resolve_in_workspace(filepath)
        if os.path.isdir(target):
            return f"Error: '{filepath}' is a directory. Provide a file name."
        _ensure_parent_dir(target)
        with open(target, "w", encoding=encoding) as f:
            f.write(content)
        return f"Successfully wrote to '{filepath}'."
    except Exception as e:
        return f"An error occurred: {e}"


# 삭제 툴 (파일/디렉터리)

@mcp.tool()
def delete_file(filepath: str) -> str:
    """
    Delete 'file' based on workspace. Reject if you turn over the directory.
    Workspace root self-deletion is a defense.
    """
    try:
        target = _resolve_in_workspace(filepath)
        if target == WORKSPACE_DIR:
            return "Error: Refuse to delete workspace root."
        if not os.path.exists(target):
            return f"Error: '{filepath}' does not exist."
        if os.path.isdir(target):
            return f"Error: '{filepath}' is a directory. Use delete_dir for directories."
        os.remove(target)
        return f"Deleted file: '{filepath}'."
    except Exception as e:
        return f"An error occurred: {e}"

@mcp.tool()
def delete_dir(directory: str, recursive: bool = False) -> str:
    """
    Delete 'directory' based on workspace.
    - recurrent=False: delete only when empty
    - recurrent=True: Delete the entire contents (rmtree)
    Workspace root deletion is a defense.
    """
    try:
        target = _resolve_in_workspace(directory)
        if target == WORKSPACE_DIR:
            return "Error: Refuse to delete workspace root."
        if not os.path.exists(target):
            return f"Error: '{directory}' does not exist."
        if not os.path.isdir(target):
            return f"Error: '{directory}' is not a directory."
        if recursive:
            shutil.rmtree(target)
        else:
            os.rmdir(target)  # 비어있지 않으면 OSError 발생 → 안내
        return f"Deleted directory: '{directory}'."
    except OSError as oe:
        return f"Error: Directory not empty or cannot remove without recursive=True. Detail: {oe}"
    except Exception as e:
        return f"An error occurred: {e}"


# CSV → JSON 변환 툴

@mcp.tool()
def csv_to_json(csv_file: str, json_file: str) -> str:
    """
Read CSV files and save them as JSON arrays.
    - csv_file: CSV file path based on workspace
    - json_file: converted JSON file path
    """
    try:
        csv_path = _resolve_in_workspace(csv_file)
        json_path = _resolve_in_workspace(json_file)
        _ensure_parent_dir(json_path)

        if not os.path.exists(csv_path):
            return f"Error: CSV file '{csv_file}' not found."

        with open(csv_path, "r", encoding="utf-8") as f:
            reader = csv.DictReader(f)
            rows = list(reader)

        with open(json_path, "w", encoding="utf-8") as f:
            json.dump(rows, f, ensure_ascii=False, indent=2)

        return f"Converted '{csv_file}' → '{json_file}' ({len(rows)} rows)."
    except Exception as e:
        return f"An error occurred: {e}"
    
app = mcp.streamable_http_app()


=======
import os, json, subprocess, sqlite3
from datetime import datetime
from mcp.server.fastmcp import FastMCP

from pymilvus import (
    connections, Collection, CollectionSchema, FieldSchema, DataType, utility
)
from sentence_transformers import SentenceTransformer

# ===============================================
# 🔧 사용자 환경 설정 (필요시 수정)
# ===============================================
E01_FILE_PATH = r"D:\mcp-server\data\Image.e01"   # 분석할 E01 파일 경로
CASE_NAME = "MyCase1"                      # 케이스 이름

CASE_BASE_DIR = r"D:\mcp-server\data"               # Autopsy 케이스 DB 저장 경로
JSON_OUTPUT_ROOT = r"D:\mcp-server\data"          # JSON 출력 경로
MILVUS_HOST = "localhost"                  # Milvus 서버 주소
MILVUS_PORT = "19530"                      # Milvus 포트
COLLECTION_NAME = "xxxx"           # Milvus 컬렉션 이름
EMBEDDING_MODEL = "paraphrase-multilingual-MiniLM-L12-v2"  # 임베딩 모델
EMBEDDING_DIM = 384                        # 모델 임베딩 차원

# Autopsy 실행 파일 후보 경로
AUTOPSY_PATHS = [
    r"C:\Program Files\Autopsy-4.22.1\bin\autopsy64.exe",
    r"C:\Program Files\Autopsy\bin\autopsy64.exe",
    r"C:\Program Files (x86)\Autopsy\bin\autopsy64.exe",
    r"C:\Autopsy\bin\autopsy64.exe"
]

# ===============================================
# MCP 서버 초기화
# ===============================================
mcp = FastMCP("forensic-mcp-server")

# ===============================================
# MCP Tool: 자동 실행 (인자 없음)
# ===============================================
@mcp.tool()
def analyze_e01_file() -> str:
    """
    This tool processes an E01 forensic image using Autopsy,
    converts the extracted data to JSON,
    and inserts the flattened records into a Milvus vector database.
    """
    try:
        # ==========================================
        # (1) Autopsy CLI 실행
        # ==========================================
        if not os.path.exists(E01_FILE_PATH):
            return f"Error: E01 not found: {E01_FILE_PATH}"

        os.makedirs(CASE_BASE_DIR, exist_ok=True)
        autopsy_exe = next((p for p in AUTOPSY_PATHS if os.path.exists(p)), None)
        if not autopsy_exe:
            return "Error: Autopsy not found."

        command = f'--createCase --caseName="{CASE_NAME}" --caseBaseDir="{CASE_BASE_DIR}" --addDataSource --dataSourcePath="{E01_FILE_PATH}" --runIngest'
        full_command = f'"{autopsy_exe}" {command}'
        result = subprocess.run(full_command, shell=True, capture_output=True, text=True, timeout=300)
        if result.returncode != 0:
            return f"Autopsy CLI error:\n{result.stderr}"

        # ==========================================
        # (2) DB → JSON 변환
        # ==========================================
        case_dir = next((os.path.join(CASE_BASE_DIR, i) for i in os.listdir(CASE_BASE_DIR) if i.startswith(CASE_NAME)), None)
        if not case_dir:
            return f"Error: Case '{CASE_NAME}' not found."
        db_path = os.path.join(case_dir, "autopsy.db")
        if not os.path.exists(db_path):
            return f"Error: autopsy.db not found at {db_path}"

        json_output_dir = os.path.join(JSON_OUTPUT_ROOT, CASE_NAME)
        os.makedirs(json_output_dir, exist_ok=True)

        conn = sqlite3.connect(db_path)
        conn.row_factory = sqlite3.Row
        cursor = conn.cursor()
        cursor.execute("SELECT name FROM sqlite_master WHERE type='table'")
        tables = [r[0] for r in cursor.fetchall()]

        unified_data = {
            "case_name": CASE_NAME,
            "conversion_date": datetime.now().isoformat(),
            "source_db": db_path,
            "total_tables": len(tables),
            "tables": {}
        }

        for t in tables:
            cursor.execute(f"SELECT * FROM {t}")
            rows = cursor.fetchall()
            if rows:
                unified_data["tables"][t] = [dict(r) for r in rows]
        conn.close()

        unified_json_path = os.path.join(json_output_dir, f"{CASE_NAME}_unified.json")
        with open(unified_json_path, "w", encoding="utf-8") as f:
            json.dump(unified_data, f, ensure_ascii=False, indent=2, default=str)

        # ==========================================
        # (3) JSON → Milvus VDB 삽입
        # ==========================================
        connections.connect("default", host=MILVUS_HOST, port=MILVUS_PORT)
        fields = [
            FieldSchema(name="id", dtype=DataType.INT64, is_primary=True, auto_id=False),
            FieldSchema(name="vector", dtype=DataType.FLOAT_VECTOR, dim=EMBEDDING_DIM),
            FieldSchema(name="text", dtype=DataType.VARCHAR, max_length=65535),
        ]
        schema = CollectionSchema(fields, description="Autopsy case artifacts")

        if utility.has_collection(COLLECTION_NAME):
            utility.drop_collection(COLLECTION_NAME)
        collection = Collection(name=COLLECTION_NAME, schema=schema)

        index_params = {
            "metric_type": "IP",
            "index_type": "HNSW",
            "params": {"M": 8, "efConstruction": 64}
        }
        collection.create_index(field_name="vector", index_params=index_params)

        # flatten JSON rows
        flat_records = []
        for table, rows in unified_data["tables"].items():
            for row in rows:
                flat_records.append(" | ".join([f"{table}.{k}: {v}" for k, v in row.items()]))

        if not flat_records:
            return f"⚠️ No data extracted from JSON for {CASE_NAME}."

        model = SentenceTransformer(EMBEDDING_MODEL)
        vectors = model.encode(flat_records, convert_to_numpy=True)
        ids = list(range(len(flat_records)))

        data_to_insert = [ids, vectors, flat_records]
        collection.insert(data_to_insert)
        collection.flush()

        return f"""
        ✅ Complete E01 → JSON → VDB finished!
        - Case: {CASE_NAME}
        - JSON: {unified_json_path}
        - Rows inserted: {len(flat_records)}
        - Collection: {COLLECTION_NAME}
        """

    except Exception as e:
        return f"Error in workflow: {e}"

# ===============================================
# MCP 서버 실행
# ===============================================
app = mcp.streamable_http_app()

if __name__ == "__main__":
    uvicorn.run(app, host="127.0.0.1", port=8080)
>>>>>>> 1194661 (ccit2)
