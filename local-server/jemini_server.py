# jemini_server.py
from fastapi import FastAPI
from pydantic import BaseModel
import subprocess
import sys
import io
import os
from pathlib import Path

# 콘솔 출력 한글 깨짐 방지 (윈도우)
sys.stdout = io.TextIOWrapper(sys.stdout.detach(), encoding='utf-8')
sys.stderr = io.TextIOWrapper(sys.stderr.detach(), encoding='utf-8')

# 🔹 이 파일(jemini_server.py)이 있는 디렉터리 기준
BASE_DIR = Path(__file__).resolve().parent


def ask_gemini_final(prompt: str) -> str:
    """
    node_modules 폴더가 BASE_DIR 아래에 있다고 가정:
      BASE_DIR/
        jemini_server.py
        node_modules/.bin/gemini.cmd
    """
    # 우선 .cmd 시도
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
        command = [
            str(gemini_cmd_path),
            prompt,
            "--output-format", "text",
            "--yolo"
        ]

        process = subprocess.run(
            command,
            capture_output=True,
            text=True,
            encoding='utf-8',
            shell=True,          # .cmd 실행 위해 유지
            cwd=str(BASE_DIR),   # 🔹 항상 프로젝트 루트에서 실행
        )

        if process.returncode == 0:
            return process.stdout.strip()
        else:
            return f"Error Code: {process.returncode}\nMessage: {process.stderr}"

    except Exception as e:
        return f"Python Script Error: {str(e)}"


# --- FastAPI 서버 설정 ---
app = FastAPI()


class ChatRequest(BaseModel):
    prompt: str


@app.post("/chat")
async def chat_endpoint(request: ChatRequest):
    print(f"[요청 수신] {request.prompt}")
    response_text = ask_gemini_final(request.prompt)
    print(f"[응답 완료] {response_text[:30]}...")
    return {"response": response_text}


if __name__ == "__main__":
    import uvicorn
    print("=== Gemini MCP API 서버 시작 (http://localhost:8000) ===")
    uvicorn.run(app, host="0.0.0.0", port=8000)
