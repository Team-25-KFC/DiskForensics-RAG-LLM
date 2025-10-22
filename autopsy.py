import os, subprocess, sqlite3, json
from datetime import datetime
from mcp.server.fastmcp import FastMCP

# MCP 서버 인스턴스는 main.py에서 가져오도록 import 후 사용
from main import mcp

@mcp.tool()
def analyze_e01_file(e01_file_path: str = None, case_name: str = None, case_base_dir: str = "E:\\lee\\db") -> str:
    try:
        if not e01_file_path or not case_name:
            # 케이스 목록 조회
            if not os.path.exists(case_base_dir):
                return f"Error: Case directory not found: {case_base_dir}"
            
            cases = []
            for item in os.listdir(case_base_dir):
                item_path = os.path.join(case_base_dir, item)
                if os.path.isdir(item_path):
                    db_path = os.path.join(item_path, "autopsy.db")
                    cases.append({
                        "case_name": item,
                        "case_path": item_path,
                        "db_path": db_path,
                        "db_exists": os.path.exists(db_path)
                    })
            return f"📋 Available Autopsy Cases:\n{json.dumps(cases, ensure_ascii=False, indent=2)}"
        
        # E01 분석 모드
        if not os.path.exists(e01_file_path):
            return f"Error: E01 file not found: {e01_file_path}"
        
        os.makedirs(case_base_dir, exist_ok=True)
        
        autopsy_paths = [
            r"C:\Program Files\Autopsy-4.20.0\bin\autopsy64.exe",
            r"C:\Program Files\Autopsy\bin\autopsy64.exe",
            r"C:\Program Files (x86)\Autopsy\bin\autopsy64.exe",
            r"C:\Autopsy\bin\autopsy64.exe"
        ]
        
        autopsy_exe = next((p for p in autopsy_paths if os.path.exists(p)), None)
        if not autopsy_exe:
            return "Error: Autopsy not found. Please check installation path."
        
        command = f'--createCase --caseName="{case_name}" --caseBaseDir="{case_base_dir}" --addDataSource --dataSourcePath="{e01_file_path}" --runIngest'
        full_command = f'"{autopsy_exe}" {command}'
        
        try:
            result = subprocess.run(full_command, shell=True, capture_output=True, text=True, timeout=300)
            autopsy_result = result.stdout if result.returncode == 0 else f"Error:\n{result.stderr}"
        except subprocess.TimeoutExpired:
            autopsy_result = "Error: Autopsy CLI command timed out (5 minutes)"
        except Exception as e:
            autopsy_result = f"Error running Autopsy CLI: {e}"
        
        if "error" in autopsy_result.lower() or "failed" in autopsy_result.lower():
            return f"Autopsy analysis failed:\n{autopsy_result}"
        
        # 케이스 디렉토리 및 DB 확인
        case_dir = next((os.path.join(case_base_dir, d) for d in os.listdir(case_base_dir) if d.startswith(case_name)), None)
        if not case_dir:
            return f"Error: Case '{case_name}' not found in {case_base_dir}"
        
        db_path = os.path.join(case_dir, "autopsy.db")
        if not os.path.exists(db_path):
            return f"Error: autopsy.db not found at {db_path}"
        
        # JSON 변환
        json_output_dir = os.path.join("E:\\lee\\json", case_name)
        os.makedirs(json_output_dir, exist_ok=True)
        
        conn = sqlite3.connect(db_path)
        conn.row_factory = sqlite3.Row
        cursor = conn.cursor()
        
        cursor.execute("SELECT name FROM sqlite_master WHERE type='table' ORDER BY name")
        tables = [row[0] for row in cursor.fetchall()]
        
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
                cursor.execute(f"SELECT * FROM {table_name}")
                rows = cursor.fetchall()
                if not rows:
                    conversion_results.append(f"⏭️ {table_name}: Empty table (skipped)")
                    continue
                unified_data["tables"][table_name] = [dict(row) for row in rows]
                non_empty_tables += 1
                conversion_results.append(f"✅ {table_name}: {len(rows)} rows")
            except Exception as e:
                conversion_results.append(f"❌ {table_name}: Error - {e}")
        
        conn.close()
        
        unified_json_path = os.path.join(json_output_dir, f"{case_name}_unified.json")
        with open(unified_json_path, 'w', encoding='utf-8') as f:
            json.dump(unified_data, f, ensure_ascii=False, indent=2, default=str)
        
        # summary
        summary_file = os.path.join(json_output_dir, "unified_conversion_summary.json")
        with open(summary_file, 'w', encoding='utf-8') as f:
            json.dump({
                "case_name": case_name,
                "conversion_date": datetime.now().isoformat(),
                "source_db": db_path,
                "output_file": unified_json_path,
                "total_tables": len(tables),
                "non_empty_tables": non_empty_tables,
                "empty_tables": len(tables)-non_empty_tables,
                "conversion_results": conversion_results
            }, f, ensure_ascii=False, indent=2)
        
        return f"✅ Complete E01 Analysis & Unified JSON Conversion!\nAutopsy: {autopsy_result}\nOutput: {unified_json_path}"
        
    except Exception as e:
        return f"Error in complete E01 analysis workflow: {e}"
