#!/usr/bin/env python3
# -*- coding: utf-8 -*-
from mcp.server.fastmcp import FastMCP
from pathlib import Path
import subprocess, shlex, os, uuid, threading, time
from typing import Dict, Any
import uvicorn

# ─────────────────────────
# MCP 서버 이름
# ─────────────────────────
mcp = FastMCP("seungwon_forensic_min")

# ─────────────────────────
# 상수 & 전역
# ─────────────────────────
ROOTDIR = Path(r"C:\GitHub\SeungWon")
SCRIPT  = ROOTDIR / "Final" / "main.py"

LOGDIR  = ROOTDIR / "logs"
LOGDIR.mkdir(exist_ok=True)

DEFAULT_PYTHON_EXE = Path(
    r"C:\Users\ksw02\AppData\Local\Programs\Python\Python313\python.exe"
)

JOBS: Dict[str, Dict[str, Any]] = {}


def _get_python() -> Path:
    """항상 기본 파이썬만 사용 (툴 인자 없음)."""
    return DEFAULT_PYTHON_EXE


# ─────────────────────────
# 툴 1: hello (동작 테스트용)
# ─────────────────────────
@mcp.tool()
def hello(name: str) -> str:
    """단순 동작 확인용 인사 툴"""
    return f"Hello, {name}!"


# ─────────────────────────
# 툴 2: 포렌식 작업 시작 (인자 없음)
# ─────────────────────────
@mcp.tool()
def start_forensic_job() -> Dict[str, Any]:
    """
    E01 파싱 등 오래 걸리는 포렌식 작업을 백그라운드에서 시작.
    인자는 받지 않고, server.py 안에서 고정 경로를 사용함.
    """
    if not ROOTDIR.exists():
        return {"ok": False, "error": f"작업 루트 없음: {ROOTDIR}"}
    if not SCRIPT.exists():
        return {"ok": False, "error": f"main.py 없음: {SCRIPT}"}

    py = _get_python().as_posix()
    cmd = [py, str(SCRIPT)]

    job_id = str(uuid.uuid4())
    log_path = LOGDIR / f"{job_id}.log"

    try:
        log_file = open(log_path, "w", encoding="utf-8")

        proc = subprocess.Popen(
            cmd,
            cwd=str(ROOTDIR),
            stdout=log_file,
            stderr=subprocess.STDOUT,
            text=True,
            bufsize=1,
        )

        JOBS[job_id] = {
            "job_id": job_id,
            "pid": proc.pid,
            "log_path": str(log_path),
            "start_time": time.time(),
            "status": "running",
            "proc": proc,
        }

        def _monitor():
            ret = proc.wait()
            JOBS[job_id]["status"] = "done"
            JOBS[job_id]["exit_code"] = ret
            log_file.close()

        threading.Thread(target=_monitor, daemon=True).start()

        return {
            "ok": True,
            "job_id": job_id,
            "cmd": cmd,
            "log_path": str(log_path),
            "message": "포렌식 작업이 백그라운드에서 시작되었습니다.",
        }

    except Exception as e:
        try:
            log_file.close()
        except Exception:
            pass
        return {
            "ok": False,
            "error": f"작업 시작 예외: {e.__class__.__name__}: {e}",
            "cmd": cmd,
        }


# ─────────────────────────
# 툴 3: 상태 확인 (옵션)
# ─────────────────────────
@mcp.tool()
def check_forensic_job_status(job_id: str, tail_lines: int = 30) -> Dict[str, Any]:
    """start_forensic_job 으로 시작한 작업 상태 확인."""
    job = JOBS.get(job_id)
    if not job:
        return {"ok": False, "error": f"job_id '{job_id}' 없음"}

    log_path = Path(job["log_path"])
    log_tail = ""
    if log_path.exists():
        with log_path.open("r", encoding="utf-8", errors="replace") as f:
            lines = f.readlines()
            log_tail = "".join(lines[-tail_lines:])
    else:
        log_tail = "(로그 파일 아직 없음)"

    return {
        "ok": True,
        "job_id": job_id,
        "status": job["status"],
        "exit_code": job.get("exit_code"),
        "log_tail": log_tail,
    }


# ─────────────────────────
# FastMCP HTTP 앱
# ─────────────────────────
app = mcp.streamable_http_app()

if __name__ == "__main__":
    uvicorn.run(app, host="127.0.0.1", port=3000)
