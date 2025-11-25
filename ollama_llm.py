import requests
from typing import Any

from langflow.custom.custom_component.component import Component
from langflow.io import (
    MessageInput,
    Output,
    StrInput,
    BoolInput,
    MultilineInput,  # ✅ 여러 줄 프롬프트용
)
from langflow.schema.message import Message
from langflow.schema.data import Data


class OllamaGenerate(Component):
    """
    Chat Input 같은 이전 노드에서 받은 메시지 + 노드 안에서 쓴 프롬프트를
    Ollama /api/generate 로 보내고,
    응답 텍스트를 다시 Message로 돌려주는 컴포넌트.
    """

    display_name = "Ollama Generate"
    description = "Send text to a local Ollama model via /api/generate and return the response."
    icon = "Ollama"
    name = "OllamaGenerate"

    # -------- 입력 정의 --------
    inputs = [
        # 1) 앞 노드에서 들어오는 메인 프롬프트 (Message / Text 둘 다 허용)
        MessageInput(
            name="input_message",
            display_name="Input",
            info="이전 노드에서 받은 텍스트/Message. 그대로 Ollama 프롬프트로 사용됩니다.",
            input_types=["Message", "Text"],
            required=True,
        ),
        # 2) 노드 안에서 직접 쓰는 추가 프롬프트 (여러 줄 가능)
        MultilineInput(
            name="node_prompt",
            display_name="Node Prompt",
            info="노드 안에서 직접 입력하는 추가 프롬프트. Chat 입력과 함께 합쳐집니다.",
            value="",
        ),
        # 3) 선택적인 시스템 메시지 (역할 지정용)
        StrInput(
            name="system_message",
            display_name="System Message",
            info="모델에게 주고 싶은 지시(system prompt). 비워두면 사용하지 않습니다.",
            advanced=True,
            value="",
        ),
        # 4) 모델 이름
        StrInput(
            name="model_name",
            display_name="Model Name",
            info="ollama list 에 표시되는 모델 이름 그대로 입력하세요.",
            # ⚠️ 네 ollama 환경에서 실제 이름 확인해서 필요하면 바꿔줘
            value="ogito-2.1:671b-cloud",
        ),
        # 5) Ollama /api/generate URL
        StrInput(
            name="base_url",
            display_name="Base URL",
            info="Ollama /api/generate 엔드포인트 URL.",
            value="http://localhost:11434/api/generate",
        ),
        # 6) 스트리밍 여부
        BoolInput(
            name="stream",
            display_name="Stream",
            info="Ollama 스트리밍 응답 사용 여부. LangFlow에서는 False 권장.",
            value=False,
            advanced=True,
        ),
    ]

    # -------- 출력 정의 --------
    outputs = [
        Output(
            name="response",
            display_name="Model Response",
            type_=Message,   # Chat Output이 바로 받을 수 있는 타입
            method="run",
        )
    ]

    # -------- 실제 실행 로직 --------
    def run(self) -> Message:
        """
        1) self.input_message 에서 텍스트를 꺼내고
        2) self.node_prompt, self.system_message 와 합쳐서 최종 prompt 생성
        3) Ollama /api/generate 로 HTTP 요청을 보내고
        4) 응답 텍스트를 Message(text=...) 로 감싸서 반환
        """

        # ----- 1) 입력 메시지에서 텍스트 꺼내기 -----
        raw_input = self.input_message
        print("[OllamaGenerate] raw input_message:", repr(raw_input), type(raw_input))

        if isinstance(raw_input, Message):
            user_text = raw_input.text or ""
        elif isinstance(raw_input, Data):
            try:
                user_text = str(raw_input.data or "")
            except Exception:
                user_text = ""
        elif isinstance(raw_input, str):
            user_text = raw_input
        else:
            try:
                user_text = str(raw_input) if raw_input is not None else ""
            except Exception:
                user_text = ""

        node_prompt = self.node_prompt or ""
        system_message = self.system_message or ""

        # ----- 2) system_message / node_prompt / user_text 합쳐서 최종 프롬프트 만들기 -----
        parts = []
        if system_message.strip():
            parts.append(system_message.strip())
        if node_prompt.strip():
            parts.append(node_prompt.strip())
        if user_text.strip():
            parts.append(user_text.strip())

        prompt = "\n\n".join(parts)

        if not prompt:
            print("[OllamaGenerate] 빈 프롬프트가 전달되었습니다.")
            return Message(text="[OllamaGenerate] 빈 프롬프트입니다.")

        # ----- 3) Ollama 설정값 읽기 -----
        model_name = self.model_name or "ogito-2.1:671b-cloud"
        base_url = self.base_url or "http://localhost:11434/api/generate"
        stream = bool(self.stream)

        payload = {
            "model": model_name,
            "prompt": prompt,
            "stream": stream,
        }

        print("[OllamaGenerate] 요청 payload:", payload)

        # ----- 4) Ollama /api/generate 호출 -----
        res = requests.post(base_url, json=payload)

        if res.status_code != 200:
            print("[OllamaGenerate] HTTP Status:", res.status_code)
            print("[OllamaGenerate] Body:", res.text)
            res.raise_for_status()

        data = res.json()
        print("[OllamaGenerate] 응답 JSON:", data)

        # ----- 5) 응답 텍스트 뽑기 -----
        answer_text = ""
        if isinstance(data, dict):
            # Ollama 기본: {"response": "...", "done": true}
            answer_text = (
                data.get("response")
                or data.get("output")
                or data.get("message")
                or data.get("content")
                or ""
            )
        else:
            answer_text = str(data)

        if not answer_text:
            answer_text = "[OllamaGenerate] 응답에 텍스트 필드를 찾지 못했습니다:\n{}".format(
                data
            )

        return Message(text=answer_text)
