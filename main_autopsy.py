import os, json, csv, shutil
import subprocess
from typing import List, Dict, Any, Optional
from mcp.server.fastmcp import FastMCP

mcp = FastMCP("forensic-mcp-server")


# ===============================================
# 작업공간(샌드박스) 설정: MCP_WORKSPACE 환경 변수 사용
# ===============================================

# 1. 환경 변수 MCP_WORKSPACE에서 경로를 가져옵니다.
WORKSPACE_DIR = os.environ.get("MCP_WORKSPACE") 

if WORKSPACE_DIR:
    # 환경 변수가 있으면 절대 경로로 설정
    WORKSPACE_DIR = os.path.abspath(WORKSPACE_DIR)
else:
    # 환경 변수가 없을 경우 (비상용), main.py가 있는 곳의 상위 디렉토리를 사용
    WORKSPACE_DIR = os.path.abspath("../") 
    print(f"Warning: MCP_WORKSPACE env var not found. Using default: {WORKSPACE_DIR}")

# 워크스페이스 디렉토리가 없으면 생성
os.makedirs(WORKSPACE_DIR, exist_ok=True)
print(f"MCP Server started. Workspace is set to: {WORKSPACE_DIR}")

def _resolve_in_workspace(rel_path: str) -> str:
    """Change the relative path based on mcp-server to the absolute path, and an exception occurs when leaving"""
    rel_path = rel_path or "."
    target = os.path.abspath(os.path.join(WORKSPACE_DIR, rel_path))
    # 보안 검사: 설정된 워크스페이스 밖으로 접근하는 것을 방지
    if os.path.commonpath([WORKSPACE_DIR, target]) != WORKSPACE_DIR:
        raise ValueError("Access denied: Path escapes workspace.")
    return target

def _ensure_parent_dir(path_abs: str):
    """Ensure the parent directory of the given path exists."""
    parent = os.path.dirname(path_abs) or WORKSPACE_DIR
    os.makedirs(parent, exist_ok=True)


# ===============================================
# 유틸리티 툴 (파일/디렉토리 관리)
# ===============================================
        
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


# ===============================================
# Autopsy CLI 도구들
# ===============================================


@mcp.tool()
def analyze_e01_file(e01_file_path: str = None, case_name: str = None, case_base_dir: str = "E:\\lee\\db") -> str:
    """
    E01 파일 분석 또는 케이스 목록 조회
    - e01_file_path가 있으면: E01 → DB → JSON 분석
    - e01_file_path가 없으면: 케이스 목록 조회
    """
    try:
        import sqlite3
        import json
        from datetime import datetime
        
        # 케이스 목록 조회 모드
        if not e01_file_path or not case_name:
            if not os.path.exists(case_base_dir):
                return f"Error: Case directory not found: {case_base_dir}"
            
            cases = []
            for item in os.listdir(case_base_dir):
                item_path = os.path.join(case_base_dir, item)
                if os.path.isdir(item_path):
                    db_path = os.path.join(item_path, "autopsy.db")
                    if os.path.exists(db_path):
                        cases.append({
                            "case_name": item,
                            "case_path": item_path,
                            "db_path": db_path,
                            "db_exists": True
                        })
                    else:
                        cases.append({
                            "case_name": item,
                            "case_path": item_path,
                            "db_path": db_path,
                            "db_exists": False
                        })
            
            return f"📋 Available Autopsy Cases:\n{json.dumps(cases, ensure_ascii=False, indent=2)}"
        
        # E01 분석 모드
        if not os.path.exists(e01_file_path):
            return f"Error: E01 file not found: {e01_file_path}"
        
        # 케이스 디렉토리 생성
        os.makedirs(case_base_dir, exist_ok=True)
        
        # 1. Autopsy 분석 실행 (직접 구현)
        autopsy_paths = [
            r"C:\Program Files\Autopsy-4.20.0\bin\autopsy64.exe",
            r"C:\Program Files\Autopsy\bin\autopsy64.exe",
            r"C:\Program Files (x86)\Autopsy\bin\autopsy64.exe",
            r"C:\Autopsy\bin\autopsy64.exe"
        ]
        
        autopsy_exe = None
        for path in autopsy_paths:
            if os.path.exists(path):
                autopsy_exe = path
                break
        
        if not autopsy_exe:
            return "Error: Autopsy not found. Please check installation path."
        
        # Autopsy CLI 명령어 실행
        command = f'--createCase --caseName="{case_name}" --caseBaseDir="{case_base_dir}" --addDataSource --dataSourcePath="{e01_file_path}" --runIngest'
        full_command = f'"{autopsy_exe}" {command}'
        
        try:
            result = subprocess.run(full_command, shell=True, capture_output=True, text=True, timeout=300)
            if result.returncode == 0:
                autopsy_result = f"Autopsy CLI executed successfully:\n{result.stdout}"
            else:
                autopsy_result = f"Autopsy CLI error:\n{result.stderr}"
        except subprocess.TimeoutExpired:
            autopsy_result = "Error: Autopsy CLI command timed out (5 minutes)"
        except Exception as e:
            autopsy_result = f"Error running Autopsy CLI: {e}"
        
        # 2. 분석 성공 여부 확인
        if "error" in autopsy_result.lower() or "failed" in autopsy_result.lower():
            return f"Autopsy analysis failed:\n{autopsy_result}"
        
        # 3. 케이스 디렉토리 찾기
        case_dir = None
        for item in os.listdir(case_base_dir):
            if item.startswith(case_name):
                case_dir = os.path.join(case_base_dir, item)
                break
        
        if not case_dir:
            return f"Error: Case '{case_name}' not found in {case_base_dir}"
        
        # 4. Autopsy DB 파일 경로
        db_path = os.path.join(case_dir, "autopsy.db")
        if not os.path.exists(db_path):
            return f"Error: autopsy.db not found at {db_path}"
        
        # 5. JSON 출력 디렉토리 생성
        json_output_dir = os.path.join("E:\\lee\\json", case_name)
        os.makedirs(json_output_dir, exist_ok=True)
        
        # 6. SQLite 데이터베이스 연결 및 통합 JSON 생성
        conn = sqlite3.connect(db_path)
        conn.row_factory = sqlite3.Row
        cursor = conn.cursor()
        
        # 모든 테이블 목록 조회
        cursor.execute("SELECT name FROM sqlite_master WHERE type='table' ORDER BY name")
        tables = [row[0] for row in cursor.fetchall()]
        
        # 통합 데이터 구조
        unified_data = {
            "case_name": case_name,
            "conversion_date": datetime.now().isoformat(),
            "source_db": db_path,
            "total_tables": len(tables),
            "tables": {}
        }
        
        conversion_results = []
        non_empty_tables = 0
        
        for table_name in tables:
            try:
                # 테이블의 모든 데이터 조회
                cursor.execute(f"SELECT * FROM {table_name}")
                rows = cursor.fetchall()
                
                # 빈 테이블은 건너뛰기
                if len(rows) == 0:
                    conversion_results.append(f"⏭️ {table_name}: Empty table (skipped)")
                    continue
                
                # 데이터를 딕셔너리 리스트로 변환
                data = []
                for row in rows:
                    data.append(dict(row))
                
                # 통합 데이터에 테이블 추가
                unified_data["tables"][table_name] = data
                non_empty_tables += 1
                
                conversion_results.append(f"✅ {table_name}: {len(data)} rows")
                
            except Exception as e:
                conversion_results.append(f"❌ {table_name}: Error - {e}")
        
        conn.close()
        
        # 7. 통합 JSON 파일로 저장
        unified_json_path = os.path.join(json_output_dir, f"{case_name}_unified.json")
        with open(unified_json_path, 'w', encoding='utf-8') as f:
            json.dump(unified_data, f, ensure_ascii=False, indent=2, default=str)
        
        # 8. 변환 요약 생성
        summary = {
            "case_name": case_name,
            "conversion_date": datetime.now().isoformat(),
            "source_db": db_path,
            "output_file": unified_json_path,
            "total_tables": len(tables),
            "non_empty_tables": non_empty_tables,
            "empty_tables": len(tables) - non_empty_tables,
            "conversion_results": conversion_results
        }
        
        summary_file = os.path.join(json_output_dir, "unified_conversion_summary.json")
        with open(summary_file, 'w', encoding='utf-8') as f:
            json.dump(summary, f, ensure_ascii=False, indent=2)
        
        return f"""✅ Complete E01 Analysis & Unified JSON Conversion!

🔍 Autopsy Analysis:
{autopsy_result}

📄 Unified JSON Conversion:
🎯 Conversion Completed!

📊 Summary:
- Case: {case_name}
- Total tables: {len(tables)}
- Non-empty tables: {non_empty_tables}
- Empty tables: {len(tables) - non_empty_tables}

📁 Output:
- Unified JSON: {unified_json_path}
- Summary: {summary_file}

📋 Results:
{chr(10).join(conversion_results[:10])}{'...' if len(conversion_results) > 10 else ''}"""
        
    except Exception as e:
        return f"Error in complete E01 analysis workflow: {e}"



    
# ===============================================
# 서버 실행 (FastMCP 표준)
# ===============================================

if __name__ == "__main__":
    mcp.run()
