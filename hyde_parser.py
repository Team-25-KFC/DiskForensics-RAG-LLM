import re
import json
from langflow.base.io.text import TextComponent
from langflow.io import MessageInput, Output
from langflow.schema.message import Message

class HyDEParser(TextComponent):
    display_name = "HyDE Output Parser"
    description = "Parse HyDE LLM output into question and keywords."
    documentation: str = "https://docs.langflow.org/components-processing#hyde-parser"
    icon = "square-terminal"

    inputs = [
        MessageInput(
            name="hyde_output",
            display_name="HyDE Output",
            info="Raw text or AIMessage output from the HyDE LLM",
            input_types=["Message"],
            tool_mode=True,
            required=True,
        ),
    ]

    outputs = [
        Output(display_name="Question", name="question", method="question_response"),
        Output(display_name="Keywords", name="keywords", method="keywords_response"),
    ]

    def extract_text(self, data):
        """
        HyDE 출력이 AIMessage, Message, dict, 또는 str 중 어떤 형식이든 텍스트만 추출.
        """
        # 1️ Langflow Message 객체 (가장 우선)
        if hasattr(data, 'text'):
            return str(data.text)
        if hasattr(data, 'content'):
            return str(data.content)
        
        # 2️ 문자열인 경우
        if isinstance(data, str):
            return data
        
        # 3️ dict형 (Langflow Data 객체일 수 있음)
        if isinstance(data, dict):
            # data.data.text 형태
            if "data" in data and isinstance(data["data"], dict) and "text" in data["data"]:
                return str(data["data"]["text"])
            # data 자체가 text 키를 가질 경우
            if "text" in data:
                return str(data["text"])
            # content 필드 있을 수도 있음
            if "content" in data:
                return str(data["content"])

        # 4️ Langchain 메시지 객체형 (AIMessage 등) - str 변환 후 파싱
        text = str(data)
        if "content='" in text or 'content="' in text:
            # AIMessage(content='...') 또는 content="..." 구조 추출
            match = re.search(r"content=['\"](.+?)['\"]", text, re.DOTALL)
            if match:
                return match.group(1)

        # 5️ 그냥 문자열로 변환
        return text

    def parse_text(self, text: str):
        question = None
        keywords = []

        # 텍스트가 한 줄로 되어 있을 수도 있으므로 공백으로 분리
        parts = text.strip().split()
        
        # "질문" 찾기
        if "질문" in parts:
            q_idx = parts.index("질문")
            # "질문 :" 다음부터 "키워드" 전까지가 질문 내용
            if q_idx + 2 < len(parts):
                question_parts = []
                for i in range(q_idx + 2, len(parts)):
                    if parts[i] == "키워드":
                        break
                    question_parts.append(parts[i])
                question = " ".join(question_parts).replace("'", "").replace('"', "")
        
        # "키워드" 찾기
        if "키워드" in parts:
            k_idx = parts.index("키워드")
            if k_idx + 1 < len(parts):
                keyword_parts = parts[k_idx + 1:]
                keywords = [k.replace(":", "").strip() for k in keyword_parts if k.strip()]
        
        keyword_text = " ".join(keywords)
        return question, keyword_text

    def get_parsed_data(self):
        """공통 파싱 로직"""
        try:
            # HyDE 출력에서 텍스트만 추출
            raw_data = self.hyde_output
            
            # 디버깅: LLM이 생성한 전체 내용을 로그로 남기기
            self.log(f"[DEBUG 1] 받은 데이터 타입: {type(raw_data)}")
            self.log(f"[DEBUG 2] 받은 데이터 전체 내용: {raw_data}")
            self.log(f"[DEBUG 3] raw_data.text 직접 출력: {raw_data.text}")
            self.log(f"[DEBUG 4] raw_data.text 길이: {len(str(raw_data.text))}")
            self.log(f"[DEBUG 5] raw_data.text 전체 내용: '{str(raw_data.text)}'")
            
            text = self.extract_text(raw_data)
            self.log(f"[DEBUG 6] 추출된 텍스트: '{text}'")
            
            question, keyword_text = self.parse_text(text)
            self.log(f"[DEBUG 7] 파싱된 질문: '{question}'")
            self.log(f"[DEBUG 8] 파싱된 키워드: '{keyword_text}'")

            return question or "", keyword_text or ""

        except Exception as e:
            error_message = f"Error during parsing: {str(e)}"
            self.log(error_message)
            return "", ""

    def question_response(self) -> Message:
        question, _ = self.get_parsed_data()
        return Message(text=question)

    def keywords_response(self) -> Message:
        _, keywords = self.get_parsed_data()
        return Message(text=keywords)