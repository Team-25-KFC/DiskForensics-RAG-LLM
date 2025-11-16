#!/usr/bin/env python3
# -*- coding: utf-8 -*-
from mcp.server.fastmcp import FastMCP
from pathlib import Path
import subprocess, sys, shlex, os, uuid, threading, time
from typing import Any, Dict

# MCP 툴 서버 정의
mcp = FastMCP("final-main-runner-async")

# --- 상수 정의 ---
ROOTDIR = Path(r"C:\GitHub\SeungWon")
SCRIPT  = ROOTDIR / "Final" / "main.py"
LOGDIR  = ROOTDIR / "logs"
LOGDIR.mkdir(exist_ok=True)
DEFAULT_PYTHON_EXE = Path(r"C:\Users\ksw02\AppData\Local\Programs\Python\Python313\python.exe")

# --- 전역 작업 저장소 ---
# { "job_id": { "status": "running" | "done", ... } }
JOBS: Dict[str, Dict[str, Any]] = {}

def _get_python(python_exe: str) -> Path:
    """ 유효한 파이썬 실행 파일 경로를 반환합니다. """
    return Path(python_exe) if python_exe.strip() else DEFAULT_PYTHON_EXE

# ---
# 툴 1: 작업 시작 (진동벨 받기)
# ---
@mcp.tool()
def start_forensic_job(python_exe: str = "", args: str = "") -> Dict[str, Any]:
    """
    [중요] E01 파싱 등 오래 걸리는 포렌식 작업을 '백그라운드'에서 시작합니다.
    이 툴은 즉시 'job_id'를 반환하며, 타임아웃되지 않습니다.
    작업 상태 및 결과는 'check_forensic_job_status' 툴로 확인해야 합니다.
    """
    if not ROOTDIR.exists():
        return {"ok": False, "error": f"작업 루트 폴더 없음: {ROOTDIR}"}
    if not SCRIPT.exists():
        return {"ok": False, "error": f"main.py 없음: {SCRIPT}"}

    py_path = _get_python(python_exe)
    py = py_path.as_posix()
    cmd = [py, str(SCRIPT)]
    if args.strip():
        cmd += shlex.split(args)

    job_id = str(uuid.uuid4())
    log_path = LOGDIR / f"{job_id}.log"
    
    try:
        # 로그 파일을 'w' 모드로 즉시 엽니다.
        log_file = open(log_path, "w", encoding="utf-8")

        proc = subprocess.Popen(
            cmd,
            cwd=str(ROOTDIR),
            stdout=log_file,
            stderr=subprocess.STDOUT,
            text=True,
            bufsize=1, # Line-buffered
        )

        # 작업 목록에 'running' 상태로 즉시 추가
        JOBS[job_id] = {
            "job_id": job_id,
            "pid": proc.pid,
            "log_path": str(log_path),
            "start_time": time.time(),
            "status": "running", # 중요: 초기 상태
            "proc": proc,
            "log_file_handle": log_file, # 파일 핸들 저장
        }

        def _monitor():
            """백그라운드 스레드: 프로세스 종료 감지"""
            ret = proc.wait()
            # 프로세스 종료 시 상태 업데이트
            JOBS[job_id]["status"] = "done"
            JOBS[job_id]["exit_code"] = ret
            log_file.close() # 작업 완료 시 파일 핸들 닫기

        # 모니터링 스레드 시작
        threading.Thread(target=_monitor, daemon=True).start()

        # [핵심] 즉시 job_id를 반환하여 타임아웃 방지
        return {
            "ok": True,
            "job_id": job_id,
            "cmd": cmd,
            "log_path": str(log_path),
            "message": "포렌식 작업이 백그라운드에서 시작되었습니다. 'check_forensic_job_status'로 상태를 확인하세요."
        }

    except Exception as e:
        if 'log_file' in locals() and not log_file.closed:
            log_file.close()
        return {
            "ok": False,
            "error": f"작업 시작 예외: {e.__class__.__name__}: {e}",
            "cmd": cmd,
        }

# ---
# 툴 2: 상태 확인 (진동벨 확인)
# ---
@mcp.tool()
def check_forensic_job_status(job_id: str, tail_lines: int = 30) -> Dict[str, Any]:
    """
    'start_forensic_job'으로 시작된 작업의 '현재 상태'와 '로그'를 확인합니다.
    'status'가 'running'이면 아직 실행 중, 'done'이면 완료된 것입니다.
    """
    job = JOBS.get(job_id)
    if not job:
        return {"ok": False, "error": f"job_id '{job_id}'를 찾을 수 없음"}

    log_path = Path(job["log_path"])
    log_content = ""
    
    if not log_path.exists():
        log_content = "(로그 파일이 아직 생성되지 않았거나, 대기 중입니다.)"
    else:
        try:
            # 로그 파일을 'r' 모드로 열기
            with log_path.open("r", encoding="utf-8", errors="replace") as f:
                lines = f.readlines()
                log_content = "".join(lines[-tail_lines:])
        except Exception as e:
            log_content = f"(로그 파일 읽기 오류: {e})"

    # 작업의 현재 상태와 로그(꼬리)를 반환
    return {
        "ok": True, 
        "job_id": job_id,
        "status": job["status"], # 'running' 또는 'done'
        "exit_code": job.get("exit_code"), # 'done'일 때만 값 존재
        "log_tail": log_content
    }


# --- [수정됨] ---
# FastMCP HTTP 앱 실행
# Uvicorn이 찾을 수 있도록 app 변수를 'if' 블록 밖, 전역 범위에 정의합니다.
app = mcp.streamable_http_app()

if __name__ == "__main__":
    # 이 스크립트를 'python server.py'로 직접 실행할 경우엔 의미가 없으며,
    # Uvicorn으로 실행하라는 안내 메시지입니다.
    print("MCP 서버 준비 완료. Uvicorn으로 'server:app'을 실행하세요.")
    print("예: uvicorn server:app --host 0.0.0.0 --port 3000")