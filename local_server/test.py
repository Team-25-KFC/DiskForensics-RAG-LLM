# start_all_servers.py
# -*- coding: utf-8 -*-
import subprocess
import sys
from pathlib import Path
import time
import webbrowser
import os  # ✅ 추가

ROOT_DIR = Path(__file__).resolve().parent

EMBED_SERVER = ROOT_DIR / "embed_server.py"
GEMINI_SERVER = ROOT_DIR / "jemini_server.py"

VENV_DIR = ROOT_DIR / "venv"
VENV_SCRIPTS = VENV_DIR / "Scripts"
VENV_PYTHON = VENV_SCRIPTS / "python.exe"

LANGFLOW_HOST = "127.0.0.1"
LANGFLOW_PORT = "7861"
LANGFLOW_URL = f"http://{LANGFLOW_HOST}:{LANGFLOW_PORT}"

processes = []

def _venv_env() -> dict:
    env = os.environ.copy()
    # ✅ venv Scripts를 PATH 맨 앞에
    env["PATH"] = str(VENV_SCRIPTS) + os.pathsep + env.get("PATH", "")
    # (선택) venv 힌트
    env["VIRTUAL_ENV"] = str(VENV_DIR)
    return env


def start_embed_server():
    if not EMBED_SERVER.exists():
        print(f"[WARN] embed_server.py 없음: {EMBED_SERVER}")
        return
    print("[+] embed_server.py 시작 (포트 8001 가정)")
    p = subprocess.Popen(
        [str(VENV_PYTHON), str(EMBED_SERVER)],
        cwd=str(ROOT_DIR),
        env=_venv_env(),   # ✅ 추가(안 해도 되지만 통일)
    )
    processes.append(p)


def start_gemini_server():
    if not GEMINI_SERVER.exists():
        print(f"[WARN] jemini_server.py 없음: {GEMINI_SERVER}")
        return
    print("[+] jemini_server.py 시작 (포트 8000 가정)")
    p = subprocess.Popen(
        [str(VENV_PYTHON), str(GEMINI_SERVER)],
        cwd=str(ROOT_DIR),
        env=_venv_env(),   # ✅ 추가(안 해도 되지만 통일)
    )
    processes.append(p)


def start_langflow(open_browser: bool = True):
    if not VENV_PYTHON.exists():
        print(f"[WARN] venv 파이썬을 찾을 수 없습니다: {VENV_PYTHON}")
        return

    # ✅ 여기서 uvx가 “실제로” 이 venv에 있는지 확인(디버깅용)
    uvx_exe = VENV_SCRIPTS / "uvx.exe"
    print(f"[INFO] uvx.exe expected at: {uvx_exe} (exists={uvx_exe.exists()})")

    print("[+] LangFlow 시작 (venv 파이썬으로 langflow run)")
    p = subprocess.Popen(
        [str(VENV_PYTHON), "-m", "langflow", "run", "--host", LANGFLOW_HOST, "--port", LANGFLOW_PORT],
        cwd=str(ROOT_DIR),
        env=_venv_env(),   # ✅ 핵심: PATH 주입
    )
    processes.append(p)

    if open_browser:
        time.sleep(7)
        print(f"[INFO] 브라우저에서 Langflow 열기: {LANGFLOW_URL}")
        webbrowser.open(LANGFLOW_URL)


if __name__ == "__main__":
    try:
        print(f"[INFO] ROOT_DIR = {ROOT_DIR}")
        print(f"[INFO] VENV_PYTHON = {VENV_PYTHON}")

        start_embed_server()
        time.sleep(1)
        start_gemini_server()
        time.sleep(1)
        start_langflow(open_browser=True)

        print("[INFO] 모든 서버 프로세스를 백그라운드로 실행했습니다.")
        print("[INFO] Ctrl+C 를 누르면 하위 프로세스를 종료합니다.")

        while True:
            time.sleep(3)

    except KeyboardInterrupt:
        print("\n[INFO] 종료 신호 감지, 하위 프로세스 종료 중...")
        for p in processes:
            try:
                p.terminate()
            except Exception:
                pass
        print("[INFO] 종료 완료")
