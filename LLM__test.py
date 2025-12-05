from fastapi import FastAPI, HTTPException
from pydantic import BaseModel
import subprocess
import sys
import io
import os

# --- 기존 로직 (Gemini CLI 실행 함수) ---
sys.stdout = io.TextIOWrapper(sys.stdout.detach(), encoding='utf-8')
sys.stderr = io.TextIOWrapper(sys.stderr.detach(), encoding='utf-8')

def ask_gemini_final(prompt):
    current_dir = os.getcwd()
    
    # [중요] 서버 실행 위치가 달라질 수 있으므로, 프로젝트 절대 경로를 박아두는 게 안전할 수 있습니다.
    # 만약 server.py가 D:\foresic_project 안에 있다면 아래 코드는 안전합니다.
    gemini_cmd_path = os.path.join(current_dir, "node_modules", ".bin", "gemini.cmd")

    if not os.path.exists(gemini_cmd_path):
        gemini_cmd_path = os.path.join(current_dir, "node_modules", ".bin", "gemini")
        if not os.path.exists(gemini_cmd_path):
             return f"오류: 실행 파일을 찾을 수 없습니다.\n경로: {gemini_cmd_path}"

    try:
        command = [
            gemini_cmd_path, 
            prompt, 
            "--output-format", "text", 
            "--yolo" 
        ]
        
        process = subprocess.run(
            command,
            capture_output=True,
            text=True,
            encoding='utf-8',
            shell=True
        )

        if process.returncode == 0:
            return process.stdout.strip()
        else:
            return f"Error Code: {process.returncode}\nMessage: {process.stderr}"

    except Exception as e:
        return f"Python Script Error: {str(e)}"

# --- FastAPI 서버 설정 ---
app = FastAPI()

# 요청 데이터 구조 정의
class ChatRequest(BaseModel):
    prompt: str

@app.post("/chat")
async def chat_endpoint(request: ChatRequest):
    """
    Langflow가 접속할 엔드포인트입니다.
    """
    print(f"[요청 수신] {request.prompt}")
    
    response_text = ask_gemini_final(request.prompt)
    
    print(f"[응답 완료] {response_text[:30]}...")
    
    return {"response": response_text}

# 실행 안내
if __name__ == "__main__":
    import uvicorn
    print("=== Gemini MCP API 서버 시작 (http://localhost:8000) ===")
    uvicorn.run(app, host="0.0.0.0", port=8000)