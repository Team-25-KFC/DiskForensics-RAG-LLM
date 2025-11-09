import re
import json
import psycopg2
from sentence_transformers import SentenceTransformer
from pymilvus import connections, Collection, FieldSchema, CollectionSchema, DataType, utility
import torch
from langflow.custom.custom_component.component import Component
from langflow.io import MessageInput, Output
from langflow.schema.data import Data
from langflow.schema.message import Message
import requests
import numpy as np

# ================================================
# 1️⃣ 통합 컴포넌트
# ================================================
class ForensicSearchAndUpload(Component):
    display_name = "Forensic Extract → PostgreSQL → Milvus"
    description = "LangFlow Message에서 JSON을 추출하고 PostgreSQL 검색 후 Milvus 업로드까지 수행합니다."
    icon = "database"

    inputs = [
        MessageInput(
            name="input_message",
            display_name="Input Message",
            info="LangFlow Message 객체 (text 필드 내 JSON 블록 포함)",
            input_types=["Message"],
            required=True,
        ),
    ]

    outputs = [
        Output(
            display_name="Upload Summary",
            name="results",
            type_=Data,
            method="run",
        )
    ]

    def run(self) -> Data:
        try:
            self.log("🧩 ForensicTextExtractor 시작")

            raw_message = self.input_message
            if isinstance(raw_message, Message):
                data = raw_message.data
            else:
                data = raw_message

            text_field = None
            if isinstance(data, dict) and "text" in data:
                text_field = data["text"]
            elif hasattr(data, "text"):
                text_field = getattr(data, "text", None)
            else:
                raise ValueError("Message 데이터에 'text' 필드가 없습니다.")

            if not text_field:
                raise ValueError("text 필드가 비어 있습니다.")

            # ```json``` 블록 추출
            json_blocks = re.findall(r"```json\s*(\{.*?\})\s*```", text_field, re.DOTALL)
            self.log(f"📦 JSON 블록 {len(json_blocks)}개 감지됨")

            texts = []
            for block in json_blocks:
                try:
                    parsed = json.loads(block)
                    texts.append(parsed)
                except json.JSONDecodeError as e:
                    self.log(f"⚠️ JSON 파싱 실패: {e}")

            formatted_json = json.dumps({"count": len(texts), "texts": texts}, indent=2, ensure_ascii=False)
            self.log(f"✅ 추출 완료:\n{formatted_json}")

            # ================================================
            # 2️⃣ PostgreSQL 연결
            # ================================================
            self.log("🔗 PostgreSQL 연결 시도 중...")

            DB_CONFIG = {
                "host": "localhost",
                "dbname": "forensic_db",
                "user": "postgres",
                "password": "admin123",
            }

            conn = psycopg2.connect(**DB_CONFIG)
            cur = conn.cursor()
            self.log("✅ PostgreSQL 연결 성공")

            # ================================================
            # 3️⃣ 테이블 목록 조회
            # ================================================
            cur.execute("""
                SELECT table_name
                FROM information_schema.tables
                WHERE table_schema='public'
                  AND (
                      table_name LIKE '%_Output_tagged'
                      OR table_name LIKE '%_Output'
                      OR table_name LIKE '%_ASEPs_Output%'
                      OR table_name LIKE '%_UserActivity_Output%'
                      OR table_name LIKE 'view_%'
                  )
                ORDER BY table_name;
            """)
            tables = [t[0] for t in cur.fetchall()]
            self.log(f"📋 {len(tables)}개 테이블 확인됨: {', '.join(tables)}")

            matched_rows = []
            summary = {}
            total_hits = 0

            # ================================================
            # 4️⃣ keyword 파싱 및 검색 (AND / OR 완전 지원)
            # ================================================

            tags = json.loads(formatted_json)["texts"]
            self.log(f"🔍 {len(tags)}개의 태그에서 키워드 검색 시작")

            for tag in tags:
                text_desc = tag.get("text", "")
                # Keywords 부분만 추출
                if "Keywords:" in text_desc:
                    keywords_part = text_desc.split("Keywords:")[-1]
                    keywords = [k.strip() for k in keywords_part.split(",") if k.strip()]
                else:
                    keywords = []

                self.log(f"🧠 [{text_desc[:80]}...] → {len(keywords)} keywords 감지")

                for kw in keywords:
                    kw = kw.replace("\\", "\\\\")  # 백슬래시 이스케이프

                    for table_name in tables:
                        # 컬럼 정보 가져오기
                        cur.execute("""
                            SELECT column_name
                            FROM information_schema.columns
                            WHERE table_schema='public' AND table_name=%s;
                        """, (table_name,))
                        columns = [c[0] for c in cur.fetchall()]

                        # 검색 컬럼 자동 선택
                        if {"type", "description"}.issubset(set(columns)):
                            concat_expr = "COALESCE(type,'') || ' ' || COALESCE(description,'')"
                        elif {"keypath", "value", "data"}.issubset(set(columns)):
                            concat_expr = "COALESCE(keypath,'') || ' ' || COALESCE(value,'') || ' ' || COALESCE(data,'')"
                        else:
                            concat_expr = " || ' ' || ".join([f"COALESCE({col},'')" for col in columns if col not in ('id',)])

                        # 논리 연산자 처리 (행 단위 매칭)
                        if " AND " in kw:
                            parts = [p.strip() for p in kw.split("AND") if p.strip()]
                            condition = " AND ".join([f"({concat_expr} ILIKE '%{p}%')" for p in parts])
                        elif " OR " in kw:
                            parts = [p.strip() for p in kw.split("OR") if p.strip()]
                            condition = " OR ".join([f"({concat_expr} ILIKE '%{p}%')" for p in parts])
                        else:
                            condition = f"{concat_expr} ILIKE '%{kw}%'"

                        query = f'SELECT * FROM "{table_name}" WHERE {condition};'
                        self.log(f"🧾 SQL 실행: {query}")

                        try:
                            cur.execute(query)
                            rows = cur.fetchall()
                            if rows:
                                matched_rows.extend([(table_name, kw, r) for r in rows])
                                self.log(f"✅ [{table_name}] '{kw}' → {len(rows)}개 행 일치")
                            else:
                                self.log(f"❌ [{table_name}] '{kw}' 일치 없음")
                        except Exception as e:
                            self.log(f"⚠️ SQL 오류 ({table_name}, '{kw}'): {e}")
                            conn.rollback()



            # ================================================
            # 5️⃣ Milvus 업로드 (키워드 매칭 결과만 저장)
            # ================================================

            COLLECTION_NAME = "tag_test"
            DIM = 384  # all-MiniLM-L12-v2 dimension
            MODEL_NAME = "text-embedding-sentence-transformers_all-minilm-l12-v2"
            API_URL = "http://localhost:1234/v1/embeddings"

            self.log(f"🚀 Milvus 연결 중 ({COLLECTION_NAME})...")
            connections.connect("default", host="localhost", port="19530")

            # 기존 collection 제거 후 새로 생성
            if utility.has_collection(COLLECTION_NAME):
                utility.drop_collection(COLLECTION_NAME)
                self.log(f"🧹 기존 collection '{COLLECTION_NAME}' 삭제됨")

            fields = [
                FieldSchema(name="id", dtype=DataType.INT64, is_primary=True, auto_id=True),
                FieldSchema(name="text", dtype=DataType.VARCHAR, max_length=2000),
                FieldSchema(name="vector", dtype=DataType.FLOAT_VECTOR, dim=DIM),
            ]
            schema = CollectionSchema(fields, description="Forensic keyword search results")
            collection = Collection(COLLECTION_NAME, schema)
            self.log(f"✅ 새 collection '{COLLECTION_NAME}' 생성 완료")

            # ================================================
            # 🔍 PostgreSQL에서 키워드로 매칭된 결과 추출 (Milvus 입력용)
            # ================================================
            texts = []
            self.log(f"🔥 Milvus insert 전 matched_rows 확인: {len(matched_rows)}")

            for table_name, kw, row in matched_rows:
                # 현재 테이블 컬럼 이름 가져오기
                cur.execute("""
                    SELECT column_name
                    FROM information_schema.columns
                    WHERE table_schema='public' AND table_name=%s;
                """, (table_name,))
                columns = [c[0] for c in cur.fetchall()]

                # 행 데이터를 {컬럼명: 값} 형태로 매핑
                row_dict = {columns[i]: str(row[i]) for i in range(len(columns)) if row[i] is not None}

                # 불필요한 필드(예: id, tag 등) 제거 가능
                for field in ["id", "tag"]:  # 필요시 추가: "deleted", "recursive", 등
                    row_dict.pop(field, None)

                # 행 데이터를 JSON 문자열로 변환 (임베딩에 쓸 핵심 데이터만)
                json_text = json.dumps(row_dict, ensure_ascii=False)

                # Milvus에는 순수 JSON 본문만 저장
                texts.append(json_text)

            # 중복 제거
            texts = list(dict.fromkeys(texts))
            self.log(f"🧾 중복 제거 후 최종 삽입 대상: {len(texts)}개")

            # ================================================
            # 💾 Milvus 업로드 미리보기
            # ================================================
            self.log("🧩 Milvus 업로드 직전 데이터 미리보기 ====")
            for i, t in enumerate(texts[:10], 1):
                self.log(f"{i}. {t[:500]}")
            self.log("🧩 =====================================")


            # ================================================
            # 🧠 LM Studio API로 임베딩 요청
            # ================================================
            import requests

            try:
                response = requests.post(
                    API_URL,
                    json={
                        "model": MODEL_NAME,
                        "input": texts
                    },
                    timeout=60
                )

                if response.status_code != 200:
                    raise RuntimeError(f"❌ LM Studio 요청 실패: {response.status_code} {response.text}")

                data = response.json()
                embeddings = [item["embedding"] for item in data["data"]]

                if len(embeddings) != len(texts):
                    raise ValueError("⚠️ 임베딩 개수와 입력 텍스트 개수가 다름")

                # ✅ Milvus에 삽입
                collection.insert([texts, embeddings])
                collection.flush()
                self.log(f"✅ Milvus 업로드 완료 — {len(texts)}개 데이터 삽입됨")

                # 인덱스 생성
                collection.create_index(
                    field_name="vector",
                    index_params={
                        "index_type": "IVF_FLAT",
                        "metric_type": "COSINE",
                        "params": {"nlist": 1024}
                    }
                )
                self.log("✅ Milvus 인덱스 생성 완료")

            except Exception as e:
                self.log(f"❌ LM Studio 임베딩 실패: {e}")
                return Data(data={"error": str(e)})




            # ================================================
            # 6️⃣ 요약 로그 출력
            # ================================================
            summary_json = json.dumps({
                "status": "success",
                "total_hits": total_hits,
                "matched_tables": summary
            }, indent=2, ensure_ascii=False)

            self.log(f"📊 요약 결과:\n{summary_json}")

            return Data(data={"status": "success", "hits": total_hits, "summary": summary})

        except Exception as e:
            self.log(f"❌ 예외 발생: {e}")
            return Data(data={"error": str(e)})
