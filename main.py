import os, shutil
from typing import List
from mcp.server.fastmcp import FastMCP

# MCP 서버 초기화
mcp = FastMCP("forensic-mcp-server")

# ===============================================
# 작업공간(샌드박스) 설정
# ===============================================
WORKSPACE_DIR = os.environ.get("MCP_WORKSPACE")

if WORKSPACE_DIR:
    WORKSPACE_DIR = os.path.abspath(WORKSPACE_DIR)
else:
    WORKSPACE_DIR = os.path.abspath("../")
    print(f"Warning: MCP_WORKSPACE env var not found. Using default: {WORKSPACE_DIR}")

os.makedirs(WORKSPACE_DIR, exist_ok=True)
print(f"MCP Server started. Workspace is set to: {WORKSPACE_DIR}")

# ===============================================
# 경로/디렉토리 유틸
# ===============================================
def _resolve_in_workspace(rel_path: str) -> str:
    rel_path = rel_path or "."
    target = os.path.abspath(os.path.join(WORKSPACE_DIR, rel_path))
    if os.path.commonpath([WORKSPACE_DIR, target]) != WORKSPACE_DIR:
        raise ValueError("Access denied: Path escapes workspace.")
    return target

def _ensure_parent_dir(path_abs: str):
    parent = os.path.dirname(path_abs) or WORKSPACE_DIR
    os.makedirs(parent, exist_ok=True)

# ===============================================
# 파일/디렉토리 툴
# ===============================================
@mcp.tool()
def list_files(directory: str = ".") -> List[str]:
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
    try:
        target = _resolve_in_workspace(directory)
        os.makedirs(target, exist_ok=True)
        return f"Directory ensured: '{directory}'."
    except Exception as e:
        return f"An error occurred: {e}"

@mcp.tool()
def read_file(filepath: str, encoding: str = "utf-8") -> str:
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
    try:
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

@mcp.tool()
def delete_file(filepath: str) -> str:
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
            os.rmdir(target)
        return f"Deleted directory: '{directory}'."
    except OSError as oe:
        return f"Error: Directory not empty or cannot remove without recursive=True. Detail: {oe}"
    except Exception as e:
        return f"An error occurred: {e}"

# ===============================================
# 외부 모듈 로드 (Autopsy & JSON)
# ===============================================
import autopsy
import json

# ===============================================
# 서버 실행
# ===============================================
if __name__ == "__main__":
    mcp.run()
