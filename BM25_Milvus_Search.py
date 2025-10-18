from langflow.custom.custom_component.component import Component
from langflow.io import MessageInput, StrInput, IntInput, Output
from langflow.schema.message import Message
from pymilvus import connections, Collection, utility
from typing import List, Dict


class BM25MilvusSearch(Component):
    display_name = "BM25 Milvus Search"
    description = "Milvus에서 BM25 알고리즘을 사용하여 텍스트 키워드 검색"
    documentation: str = "https://docs.langflow.org/components-retrievers"
    icon = "search"

    inputs = [
        StrInput(
            name="milvus_uri",
            display_name="Milvus URI",
            info="Milvus 서버 주소",
            value="http://localhost:19530",
            required=True,
        ),
        StrInput(
            name="collection_name",
            display_name="Collection Name",
            info="검색할 Milvus 컬렉션 이름",
            value="qqqq",
            required=True,
        ),
        MessageInput(
            name="search_keywords",
            display_name="Search Keywords",
            info="검색할 키워드 텍스트",
            input_types=["Message"],
            required=True,
        ),
        IntInput(
            name="top_k",
            display_name="Top K Results",
            info="반환할 검색 결과 개수",
            value=10,
            required=False,
        ),
    ]

    outputs = [
        Output(display_name="Results", name="results", method="search_results"),
    ]

    def connect_milvus(self):
        """Milvus 서버에 연결"""
        try:
            # 기존 연결이 있으면 해제
            try:
                connections.disconnect("default")
            except:
                pass
            
            # 새로운 연결 생성
            connections.connect(
                alias="default",
                uri=self.milvus_uri
            )
            self.log(f"Milvus 연결 성공: {self.milvus_uri}")
            return True
        except Exception as e:
            self.log(f"Milvus 연결 실패: {str(e)}")
            return False

    def check_collection_exists(self):
        """컬렉션 존재 여부 확인"""
        try:
            exists = utility.has_collection(self.collection_name)
            if exists:
                self.log(f"컬렉션 '{self.collection_name}' 존재 확인")
            else:
                self.log(f"컬렉션 '{self.collection_name}'이 존재하지 않습니다")
            return exists
        except Exception as e:
            self.log(f"컬렉션 확인 중 오류: {str(e)}")
            return False

    def extract_keywords(self, data):
        """입력 데이터에서 키워드 텍스트 추출"""
        if hasattr(data, 'text'):
            return str(data.text)
        if hasattr(data, 'content'):
            return str(data.content)
        if isinstance(data, str):
            return data
        if isinstance(data, dict):
            if "text" in data:
                return str(data["text"])
            if "content" in data:
                return str(data["content"])
        return str(data)

    def bm25_search(self, keywords: str, top_k: int = 10) -> List[Dict]:
        """
        BM25 알고리즘을 사용한 Milvus 검색
        Milvus의 query()를 사용하여 텍스트 필드 검색 후 BM25 스코어링
        """
        try:
            # 컬렉션 로드
            collection = Collection(self.collection_name)
            
            # 컬렉션 로드 (검색을 위해 메모리에 로드)
            collection.load()
            self.log(f" 컬렉션 '{self.collection_name}' 로드 완료")
            
            # 컬렉션 스키마 확인
            schema = collection.schema
            text_field = None
            for field in schema.fields:
                if field.dtype.name in ['VARCHAR', 'STRING']:
                    text_field = field.name
                    self.log(f" 텍스트 필드 발견: {text_field}")
                    break
            
            if not text_field:
                self.log(" 텍스트 필드를 찾을 수 없습니다")
                return []
            
            # 키워드 분리
            keyword_list = keywords.strip().split()
            self.log(f" 분리된 키워드: {keyword_list}")
            
            # 각 키워드에 대해 OR 검색 수행
            # Milvus query에서는 expr을 사용한 필터링
            all_results = []
            
            # 전체 데이터 가져오기 (정확한 BM25 계산을 위해 모든 데이터 조회)
            try:
                # expr 없이 전체 쿼리 (limit 최대값 사용)
                query_results = collection.query(
                    expr="",
                    output_fields=["*"],
                    limit=16384  # Milvus 최대 limit (전체 데이터 조회)
                )
                self.log(f" 쿼리 결과: {len(query_results)}개 문서 (전체 데이터 대상)")
            except Exception as e:
                # expr="" 이 안되면 전체 조회 시도
                self.log(f" 전체 쿼리 실패, 대체 방법 시도: {str(e)}")
                query_results = collection.query(
                    expr=f"{text_field} != ''",
                    output_fields=["*"],
                    limit=16384  # Milvus 최대 limit
                )
            
            # BM25 스코어 계산 (간단한 TF-IDF 기반 스코어링)
            from collections import Counter
            import math
            
            scored_results = []
            for doc in query_results:
                if text_field not in doc:
                    continue
                
                doc_text = str(doc[text_field]).lower()
                doc_terms = doc_text.split()
                
                # BM25 파라미터
                k1 = 1.5
                b = 0.75
                avgdl = sum(len(str(d.get(text_field, "")).split()) for d in query_results) / len(query_results)
                doc_len = len(doc_terms)
                
                score = 0.0
                doc_term_freq = Counter(doc_terms)
                
                for keyword in keyword_list:
                    keyword_lower = keyword.lower()
                    if keyword_lower in doc_term_freq:
                        # TF (Term Frequency)
                        tf = doc_term_freq[keyword_lower]
                        
                        # IDF 계산 (전체 문서에서 키워드 포함 개수)
                        df = sum(1 for d in query_results if keyword_lower in str(d.get(text_field, "")).lower())
                        idf = math.log((len(query_results) - df + 0.5) / (df + 0.5) + 1.0)
                        
                        # BM25 스코어
                        numerator = tf * (k1 + 1)
                        denominator = tf + k1 * (1 - b + b * (doc_len / avgdl))
                        score += idf * (numerator / denominator)
                
                if score > 0:
                    result_dict = {
                        "score": score,
                        **doc
                    }
                    scored_results.append(result_dict)
            
            # 스코어 기준으로 정렬
            scored_results.sort(key=lambda x: x['score'], reverse=True)
            
            # Top K 결과만 반환
            final_results = scored_results[:top_k]
            
            self.log(f" BM25 검색 완료: {len(final_results)} 개의 결과")
            
            return final_results
            
        except Exception as e:
            self.log(f" 검색 중 오류 발생: {str(e)}")
            import traceback
            self.log(f" 상세 오류: {traceback.format_exc()}")
            return []

    def search_results(self) -> Message:
        """검색 실행 및 결과 반환"""
        try:
            # 1. Milvus 연결
            if not self.connect_milvus():
                return Message(text="Milvus 연결 실패")
            
            # 2. 컬렉션 존재 확인
            if not self.check_collection_exists():
                return Message(text=f"컬렉션 '{self.collection_name}'이 존재하지 않습니다")
            
            # 3. 키워드 추출
            keywords = self.extract_keywords(self.search_keywords)
            self.log(f" 검색 키워드: '{keywords}'")
            
            # 4. BM25 검색 실행
            top_k = self.top_k if hasattr(self, 'top_k') and self.top_k else 10
            results = self.bm25_search(keywords, top_k)
            
            # 5. 결과 포맷팅
            if not results:
                return Message(text="검색 결과가 없습니다")
            
            # 결과를 텍스트로 변환 (벡터 필드 제외)
            result_text = f" BM25 검색 결과 (총 {len(results)}개)\n\n"
            for idx, result in enumerate(results, 1):
                result_text += f"[{idx}] Score: {result.get('score', 'N/A'):.4f}\n"
                for key, value in result.items():
                    # 벡터 필드(리스트), id, score, distance 제외
                    if key not in ['id', 'score', 'distance', 'vector'] and not isinstance(value, list):
                        result_text += f"  {key}: {value}\n"
                result_text += "\n"
            
            self.log(f" 검색 완료: {len(results)}개 결과 반환")
            
            return Message(text=result_text)

        except Exception as e:
            error_msg = f" 오류 발생: {str(e)}"
            self.log(error_msg)
            return Message(text=error_msg)
        
        finally:
            # 연결 정리
            try:
                connections.disconnect("default")
            except:
                pass

    def build(self) -> Message:
        """빌드 메서드"""
        return self.search_results()

