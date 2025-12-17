# jemini_server.py
from fastapi import FastAPI
from pydantic import BaseModel
import subprocess
import sys
import io
from pathlib import Path

# 콘솔 출력 한글 깨짐 방지 (윈도우)
# (서버 로그용이니까 errors="replace"로 안전하게 처리)
try:
    sys.stdout = io.TextIOWrapper(sys.stdout.detach(), encoding="utf-8", errors="replace")
    sys.stderr = io.TextIOWrapper(sys.stderr.detach(), encoding="utf-8", errors="replace")
except Exception:
    # 일부 환경(예: 이미 래핑된 경우)에서는 detach가 안 될 수 있으니 무시
    pass

# 🔹 이 파일(jemini_server.py)이 있는 디렉터리 기준
BASE_DIR = Path(__file__).resolve().parent


def safe_decode(data: bytes) -> str:
    """
    서브프로세스에서 받은 stdout/stderr를
    최대한 안전하게 문자열로 바꾸기 위한 헬퍼 함수.
    """
    if data is None:
        return ""

    # 1) UTF-8 우선 시도
    try:
        return data.decode("utf-8")
    except UnicodeDecodeError:
        pass

    # 2) 윈도우 한글(cp949) 시도
    try:
        return data.decode("cp949")
    except UnicodeDecodeError:
        pass

    # 3) 그래도 안 되면 UTF-8 기준으로 깨지는 부분만 치환
    return data.decode("utf-8", errors="replace")


def ask_gemini_final(prompt: str) -> str:
    """
    node_modules 폴더가 BASE_DIR 아래에 있다고 가정:
      BASE_DIR/
        jemini_server.py
        node_modules/.bin/gemini.cmd

    긴 프롬프트도 받을 수 있도록,
    prompt를 명령행 인자가 아니라 stdin으로 넘긴다.
    """
    # 우선 .cmd 시도 (윈도우)
    gemini_cmd_path = BASE_DIR / "node_modules" / ".bin" / "gemini.cmd"
    if not gemini_cmd_path.exists():
        # 유닉스 스타일 바이너리 이름도 한 번 더 시도
        gemini_cmd_path = BASE_DIR / "node_modules" / ".bin" / "gemini"
        if not gemini_cmd_path.exists():
            return (
                "오류: Gemini CLI 실행 파일을 찾을 수 없습니다.\n"
                f"시도한 경로: {gemini_cmd_path}"
            )

    try:
        # prompt를 인자로 넘기지 않고, stdin으로 전달
        command = [
            str(gemini_cmd_path),
            "--output-format", "text",
            "--yolo",
        ]

        process = subprocess.run(
            command,
            input=prompt.encode("utf-8"),  # 긴 텍스트를 stdin으로 전달 (bytes)
            capture_output=True,
            text=False,                     # 자동 디코딩 끔 (bytes로 받기)
            shell=True,                     # .cmd 실행 위해 유지
            cwd=str(BASE_DIR),              # 항상 프로젝트 루트에서 실행
        )

        stdout_text = safe_decode(process.stdout)
        stderr_text = safe_decode(process.stderr)

        if process.returncode == 0:
            return stdout_text.strip()
        else:
            return f"Error Code: {process.returncode}\nMessage: {stderr_text or 'None'}"

    except Exception as e:
        return f"Python Script Error: {str(e)}"


# --- FastAPI 서버 설정 ---
app = FastAPI()


class ChatRequest(BaseModel):
    prompt: str


@app.post("/chat")
async def chat_endpoint(request: ChatRequest):
    print(f"[요청 수신] {request.prompt[:80]}...")
    response_text = ask_gemini_final(request.prompt)
    print(f"[응답 완료] {response_text[:80]}...")
    return {"response": response_text}


if __name__ == "__main__":
    import uvicorn

    print("=== Gemini MCP API 서버 시작 (http://localhost:8000) ===")
    uvicorn.run(app, host="0.0.0.0", port=8000)
