#!/usr/bin/env python3
# -*- coding: utf-8 -*-
from mcp.server.fastmcp import FastMCP
from pathlib import Path
import subprocess, sys, shlex, os, uuid, threading, time
from typing import Any, Dict, Optional

# MCP 툴 서버 정의
mcp = FastMCP("final-main-runner-async")

# ──────────────────────────────────────────────
#  ROOTDIR / SCRIPT 자동 탐색 로직
# ──────────────────────────────────────────────

def _detect_rootdir() -> Path:
    """
    Final/main.py 위치를 최대한 자동으로 탐색해서 ROOTDIR를 결정한다.

    우선순위:
    1) 환경변수 FORENSIC_ROOTDIR 또는 SEUNGWON_ROOTDIR
    2) server.py(__file__) 기준으로 위로 올라가며 Final/main.py 존재 여부 확인
    3) server.py 주변 디렉토리 및 현재 작업 디렉토리 전체를 재귀 탐색하여 Final/main.py 찾기
    4) 그래도 못 찾으면 RuntimeError 발생 (환경변수로 지정 필요)
    """
    # 1) 환경변수 우선
    env_root = os.getenv("FORENSIC_ROOTDIR") or os.getenv("SEUNGWON_ROOTDIR")
    if env_root:
        p = Path(env_root).expanduser().resolve()
        if p.exists():
            return p

    here = Path(__file__).resolve()

    # 2) 부모 디렉토리 체인에서 Final/main.py 찾기
    for parent in [here.parent] + list(here.parents):
        candidate = parent / "Final" / "main.py"
        if candidate.exists():
            return parent

    # 3) 주변 디렉토리 전체 탐색 (server.py가 있는 폴더와 현재 작업 디렉토리 기준)
    search_roots = {here.parent, Path.cwd()}
    visited: set[Path] = set()

    def _search_under(root: Path) -> Optional[Path]:
        """root 이하에서 Final/main.py를 재귀 탐색."""
        try:
            root = root.resolve()
        except Exception:
            return None
        if root in visited or not root.exists():
            return None
        visited.add(root)

        try:
            # Final/main.py 패턴만 rglob로 탐색
            for path in root.rglob("Final/main.py"):
                # Final 폴더의 상위 폴더를 ROOTDIR로 사용
                return path.parent.parent
        except Exception:
            # 권한 문제 등은 무시
            return None
        return None

    for sr in list(search_roots):
        found = _search_under(sr)
        if found is not None:
            return found

    # 4) 완전히 실패한 경우
    raise RuntimeError(
        "Final/main.py 위치를 자동으로 찾을 수 없습니다. "
        "FORENSIC_ROOTDIR (또는 SEUNGWON_ROOTDIR) 환경변수로 루트 폴더를 지정해 주세요."
    )


ROOTDIR = _detect_rootdir()
SCRIPT  = ROOTDIR / "Final" / "main.py"
LOGDIR  = ROOTDIR / "logs"
LOGDIR.mkdir(exist_ok=True)

# ──────────────────────────────────────────────
#  전역 작업 저장소
# ──────────────────────────────────────────────
# { "job_id": { "status": "running" | "done", ... } }
JOBS: Dict[str, Dict[str, Any]] = {}

# ──────────────────────────────────────────────
#  파이썬 실행 파일 결정 로직
# ──────────────────────────────────────────────

def _get_python(python_exe: str) -> Path:
    """
    사용할 파이썬 실행 파일 경로를 결정한다.

    우선순위:
    1) 함수 인자로 들어온 python_exe (공백이 아닌 경우)
    2) 환경변수 FORENSIC_PYTHON_EXE 또는 PYTHON_EXE
    3) 현재 이 MCP 서버를 실행 중인 파이썬(sys.executable)
    """
    # 1) 인자로 직접 받은 경로가 있으면 그걸 사용
    if python_exe and python_exe.strip():
        return Path(python_exe).expanduser().resolve()

    # 2) 환경변수로 오버라이드 (옵션)
    env_exe = os.getenv("FORENSIC_PYTHON_EXE") or os.getenv("PYTHON_EXE")
    if env_exe:
        return Path(env_exe).expanduser().resolve()

    # 3) 기본값: 현재 MCP 서버를 실행 중인 파이썬
    return Path(sys.executable).resolve()


# ──────────────────────────────────────────────
#  툴 1: 작업 시작 (진동벨 받기)
# ──────────────────────────────────────────────

@mcp.tool()
def start_forensic_job(python_exe: str = "", args: str = "") -> str:
    """
    [중요] E01 파싱 등 오래 걸리는 포렌식 작업을 '백그라운드'에서 시작합니다.
    이 툴은 즉시 'job_id'를 문자열로 반환하며, 타임아웃되지 않습니다.
    작업 상태 및 결과는 'check_forensic_job_status' 툴로 확인해야 합니다.
    """
    if not ROOTDIR.exists():
        return f"[ERR] 작업 루트 폴더 없음: {ROOTDIR}"

    if not SCRIPT.exists():
        return f"[ERR] main.py 없음: {SCRIPT}"

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
            bufsize=1,  # Line-buffered
        )

        # 작업 목록에 'running' 상태로 즉시 추가
        JOBS[job_id] = {
            "job_id": job_id,
            "pid": proc.pid,
            "log_path": str(log_path),
            "start_time": time.time(),
            "status": "running",  # 중요: 초기 상태
            "proc": proc,
            "log_file_handle": log_file,  # 파일 핸들 저장
        }

        def _monitor():
            """백그라운드 스레드: 프로세스 종료 감지"""
            ret = proc.wait()
            # 프로세스 종료 시 상태 업데이트
            JOBS[job_id]["status"] = "done"
            JOBS[job_id]["exit_code"] = ret
            log_file.close()  # 작업 완료 시 파일 핸들 닫기

        # 모니터링 스레드 시작
        threading.Thread(target=_monitor, daemon=True).start()

        # 문자열로 요약 정보 반환 (Langflow에서 그대로 출력 가능)
        return (
            "[OK] 포렌식 작업이 백그라운드에서 시작되었습니다.\n"
            f"job_id   : {job_id}\n"
            f"log_path: {log_path}\n"
            f"cmd      : {' '.join(cmd)}\n"
            "※ 상태/로그는 check_forensic_job_status(job_id)로 확인하세요."
        )

    except Exception as e:
        if "log_file" in locals() and not log_file.closed:
            log_file.close()
        return (
            "[ERR] 작업 시작 예외 발생.\n"
            f"예외    : {e.__class__.__name__}: {e}\n"
            f"cmd     : {' '.join(cmd)}"
        )


# ──────────────────────────────────────────────
#  툴 2: 상태 확인 (진동벨 확인)
# ──────────────────────────────────────────────

@mcp.tool()
def check_forensic_job_status(job_id: str, tail_lines: int = 30) -> str:
    """
    'start_forensic_job'으로 시작된 작업의 '현재 상태'와 '로그 꼬리'를 확인합니다.
    반환값은 사람이 읽기 좋은 요약 문자열입니다.
    """
    job = JOBS.get(job_id)
    if not job:
        return (
            f"[ERR] job_id '{job_id}'를 찾을 수 없습니다. "
            "(서버 재시작 시 메모리 초기화되었을 수도 있음)"
        )

    log_path = Path(job["log_path"])
    if not log_path.exists():
        log_content = "(로그 파일이 아직 생성되지 않았거나, 대기 중입니다.)"
    else:
        try:
            with log_path.open("r", encoding="utf-8", errors="replace") as f:
                lines = f.readlines()
                log_content = "".join(lines[-tail_lines:])
        except Exception as e:
            log_content = f"(로그 파일 읽기 오류: {e})"

    status = job["status"]
    exit_code = job.get("exit_code")

    return (
        "[OK] 포렌식 작업 상태\n"
        f"job_id   : {job_id}\n"
        f"status   : {status}\n"
        f"exit_code: {exit_code}\n"
        f"log_path: {log_path}\n"
        "------------ 로그 꼬리 ------------\n"
        f"{log_content}"
    )


# ──────────────────────────────────────────────
#  FastMCP HTTP 앱 실행
# ──────────────────────────────────────────────

app = mcp.streamable_http_app()

if __name__ == "__main__":
    # 이 스크립트를 'python server.py'로 직접 실행할 경우엔 의미가 없으며,
    # Uvicorn으로 실행하라는 안내 메시지입니다.
    print("MCP 서버 준비 완료. Uvicorn으로 'server:app'을 실행하세요.")
    print("예: uvicorn server:app --host 0.0.0.0 --port 3000")
