from mcp.server.fastmcp import FastMCP
from pathlib import Path
import subprocess, sys, shlex, os
from typing import Any, Dict

mcp = FastMCP("final-main-runner")

# ─────────────────────────────
# 고정 설정 (VSCode 실행 환경과 최대한 동일하게)
# ─────────────────────────────
ROOTDIR = Path(r"C:\GitHub\SeungWon")          # VSCode에서 cd 하던 경로
SCRIPT  = ROOTDIR / "Final" / "main.py"        # 실제 main.py 경로
MAX_RET_LEN = 20000                            # stdout/stderr 최대 길이

# VSCode 로그 기준으로 사용하는 파이썬 3.13 경로
DEFAULT_PYTHON_EXE = Path(
    r"C:\Users\ksw02\AppData\Local\Programs\Python\Python313\python.exe"
)


@mcp.tool()
def run_final_main(
    python_exe: str = "",
    args: str = "",
    timeout_sec: int = 0,
) -> Dict[str, Any]:
    """
    C:\\GitHub\\SeungWon\\Final\\main.py를 동기 실행.

    - python_exe: 비우면 DEFAULT_PYTHON_EXE 사용
    - args: main.py에 넘길 인자 문자열 (예: "--foo bar")
    - timeout_sec: 0 또는 음수면 타임아웃 없이 실행, 양수면 해당 초까지 대기
    """
    if not ROOTDIR.exists():
        return {"ok": False, "error": f"작업 루트 폴더 없음: {ROOTDIR}"}
    if not SCRIPT.exists():
        return {"ok": False, "error": f"실행 파일 없음: {SCRIPT}"}

    # 사용할 파이썬 해석기 결정
    if python_exe.strip():
        py_path = Path(python_exe)
    else:
        py_path = DEFAULT_PYTHON_EXE

    py = py_path.as_posix()

    # 명령어 구성 (VSCode 실행 패턴과 동일: 루트폴더를 cwd로, Final/main.py 실행)
    cmd = [py, str(SCRIPT)]
    if args.strip():
        cmd += shlex.split(args)

    # // [코드 삽입 시작] run_final_main 디버그 로그
    print("[MCP] run_final_main 호출됨")
    print(f"[MCP] SCRIPT = {SCRIPT}")
    print(f"[MCP] python_exe = {py}")
    print(f"[MCP] python_exe exists = {py_path.exists()}")
    # // [코드 삽입 끝]

    try:
        # 기본 실행 옵션
        env = os.environ.copy()  # VSCode 실행 환경과 동일하게, 기존 env 그대로 사용

        run_kwargs: Dict[str, Any] = dict(
            cwd=str(ROOTDIR),      # ← VSCode와 동일하게 루트에서 실행
            capture_output=True,
            text=True,
            errors="replace",
            env=env,
        )

        if timeout_sec and timeout_sec > 0:
            run_kwargs["timeout"] = timeout_sec

        # // [코드 삽입 시작] 실제 실행 정보 디버그 출력
        print(f"[MCP] CMD = {cmd}")
        print(f"[MCP] cwd = {run_kwargs['cwd']}")
        for key in ("AIM_EXE", "E01_PATH", "KAPE_EXE", "BASE_OUT"):
            print(f"[MCP] env {key} = {env.get(key)}")
        # // [코드 삽입 끝]

        proc = subprocess.run(cmd, **run_kwargs)

        out = (proc.stdout or "")[-MAX_RET_LEN:]
        err = (proc.stderr or "")[-MAX_RET_LEN:]

        # // [코드 삽입 시작] 종료 코드 및 요약 로그
        print(f"[MCP] run_final_main 종료, exit_code = {proc.returncode}")
        if out:
            print("[MCP] --- main.py stdout (tail) ---")
            # 너무 길 수 있으니 마지막 몇 줄만 출력
            for line in out.splitlines()[-20:]:
                print(f"[MCP] {line}")
        if err:
            print("[MCP] --- main.py stderr (tail) ---")
            for line in err.splitlines()[-20:]:
                print(f"[MCP-ERR] {line}")
        # // [코드 삽입 끝]

        return {
            "ok": proc.returncode == 0,
            "exit_code": proc.returncode,
            "cmd": cmd,
            "cwd": str(ROOTDIR),
            "python_exe": str(py_path),
            "stdout": out,
            "stderr": err,
        }

    except subprocess.TimeoutExpired:
        print(f"[MCP] run_final_main 타임아웃 발생 ({timeout_sec}s)")
        return {
            "ok": False,
            "error": f"타임아웃({timeout_sec}s) 발생",
            "cmd": cmd,
            "cwd": str(ROOTDIR),
            "python_exe": str(py_path),
        }
    except FileNotFoundError as e:
        print(f"[MCP] 파이썬 exe를 찾을 수 없음: {e}")
        return {
            "ok": False,
            "error": f"파이썬 exe를 찾을 수 없음: {e}",
            "python_exe": str(py_path),
            "cmd": cmd,
            "cwd": str(ROOTDIR),
        }
    except Exception as e:
        print(f"[MCP] 예외 발생: {e.__class__.__name__}: {e}")
        return {
            "ok": False,
            "error": f"예외: {e.__class__.__name__}: {e}",
            "cmd": cmd,
            "cwd": str(ROOTDIR),
            "python_exe": str(py_path),
        }


# FastMCP HTTP 앱
app = mcp.streamable_http_app()
