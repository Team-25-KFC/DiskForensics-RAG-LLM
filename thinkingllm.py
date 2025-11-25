import requests

def ask_ollama_http(prompt: str) -> str:
    url = "http://localhost:11434/api/generate"
    payload = {
        "model": "cogito-2.1:671b-cloud",  # ollama list에 보이는 모델 이름 그대로
        "prompt": prompt,
        "stream": False,
    }

    res = requests.post(url, json=payload)

    # 디버깅용 출력 (문제 생기면 확인용)
    if res.status_code != 200:
        print("Status:", res.status_code)
        print("Body:", res.text)

    res.raise_for_status()
    data = res.json()
    return data.get("response", "")


if __name__ == "__main__":
    print("여러 줄을 입력한 뒤, 한 줄에 백틱(`)만 입력하면 전송됩니다.")
    print("예) 프롬프트 다 쓰고 마지막 줄에 그대로 ` 입력 후 엔터\n")

    lines = []
    while True:
        try:
            line = input()
        except EOFError:
            # Ctrl+Z(Windows) / Ctrl+D(Linux)로 끝낸 경우
            break

        # 종료 트리거: 백틱 한 줄만 입력
        if line.strip() == "`":
            break

        lines.append(line)

    if not lines:
        print("입력된 내용이 없습니다. 종료합니다.")
    else:
        q = "\n".join(lines)
        print("\n===== 보낸 프롬프트 =====")
        print(q)
        print("=========================\n")

        answer = ask_ollama_http(q)
        print("=== 답변 ===")
        print(answer)
