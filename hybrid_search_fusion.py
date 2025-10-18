from langflow.custom.custom_component.component import Component
from langflow.io import MessageInput, FloatInput, Output
from langflow.schema.message import Message
from typing import List, Dict
import json


class HybridSearchFusion(Component):
    display_name = "Hybrid Search Fusion"
    description = "Milvus 벡터 검색과 BM25 검색 결과를 결합하여 최종 순위 생성"
    documentation: str = "https://docs.langflow.org/components-retrievers"
    icon = "merge"

    inputs = [
        MessageInput(
            name="milvus_results",
            display_name="Milvus Results",
            info="Milvus 벡터 유사도 검색 결과 (JSON 형식)",
            input_types=["Message"],
            required=True,
        ),
        MessageInput(
            name="bm25_results",
            display_name="BM25 Results",
            info="BM25 검색 결과 (텍스트 형식)",
            input_types=["Message"],
            required=True,
        ),
        FloatInput(
            name="milvus_weight",
            display_name="Milvus Weight",
            info="Milvus 점수 가중치 (0~1)",
            value=0.5,
            required=False,
        ),
        FloatInput(
            name="bm25_weight",
            display_name="BM25 Weight",
            info="BM25 점수 가중치 (0~1)",
            value=0.5,
            required=False,
        ),
    ]

    outputs = [
        Output(display_name="Fused Results", name="fused_results", method="fuse_results"),
    ]

    def extract_text(self, data):
        """입력 데이터에서 텍스트 추출"""
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

    def parse_milvus_results(self, text: str) -> List[Dict]:
        """Milvus JSON 결과 파싱"""
        results = []
        try:
            # 먼저 전체를 JSON으로 파싱 시도 (배열 형태)
            try:
                parsed = json.loads(text)
                if isinstance(parsed, list):
                    results = parsed
                    self.log(f"Milvus 결과 파싱 완료 (JSON 배열): {len(results)}개")
                    return results
                elif isinstance(parsed, dict):
                    results = [parsed]
                    self.log(f"Milvus 결과 파싱 완료 (JSON 객체): {len(results)}개")
                    return results
            except json.JSONDecodeError:
                pass
            
            # JSON 배열 파싱 실패시 줄바꿈으로 구분된 JSON 파싱
            lines = text.strip().split('\n')
            for line in lines:
                line = line.strip()
                if line.startswith('```json'):
                    continue
                if line.startswith('```'):
                    continue
                if not line:
                    continue
                
                try:
                    result = json.loads(line)
                    if isinstance(result, dict):
                        results.append(result)
                    elif isinstance(result, list):
                        results.extend(result)
                except json.JSONDecodeError:
                    continue
            
            self.log(f"Milvus 결과 파싱 완료 (줄바꿈 구분): {len(results)}개")
            return results
        except Exception as e:
            self.log(f"Milvus 결과 파싱 오류: {str(e)}")
            return []

    def parse_bm25_results(self, text: str) -> List[Dict]:
        """BM25 텍스트 결과 파싱"""
        results = []
        try:
            lines = text.strip().split('\n')
            current_result = None
            
            for line in lines:
                line = line.strip()
                
                # 결과 시작 (예: [1] Score: 6.5163)
                if line.startswith('[') and '] Score:' in line:
                    if current_result:
                        results.append(current_result)
                    
                    # Score 추출
                    score_str = line.split('Score:')[1].strip()
                    current_result = {
                        'score': float(score_str),
                        'text': '',
                        'id': None
                    }
                
                # text 필드
                elif current_result and line.startswith('text:'):
                    current_result['text'] = line[5:].strip()
                
                # id 필드 (선택적)
                elif current_result and line.startswith('id:'):
                    try:
                        current_result['id'] = int(line[3:].strip())
                    except:
                        pass
            
            # 마지막 결과 추가
            if current_result:
                results.append(current_result)
            
            self.log(f"BM25 결과 파싱 완료: {len(results)}개")
            return results
        except Exception as e:
            self.log(f"BM25 결과 파싱 오류: {str(e)}")
            return []

    def normalize_scores(self, scores: List[float]) -> List[float]:
        """점수를 0~1 범위로 정규화"""
        if not scores:
            return []
        
        min_score = min(scores)
        max_score = max(scores)
        
        if max_score == min_score:
            return [1.0] * len(scores)
        
        return [(s - min_score) / (max_score - min_score) for s in scores]

    def fuse_results(self) -> Message:
        """두 검색 결과를 결합"""
        try:
            # 1. 입력 데이터 추출
            milvus_text = self.extract_text(self.milvus_results)
            bm25_text = self.extract_text(self.bm25_results)
            
            self.log("입력 데이터 추출 완료")
            self.log(f"DEBUG - Milvus 원본 데이터 타입: {type(self.milvus_results)}")
            self.log(f"DEBUG - Milvus 텍스트 길이: {len(milvus_text)}")
            self.log(f"DEBUG - Milvus 텍스트 앞 500자: {milvus_text[:500]}")
            
            # 2. 결과 파싱
            milvus_results = self.parse_milvus_results(milvus_text)
            bm25_results = self.parse_bm25_results(bm25_text)
            
            self.log(f"DEBUG - Milvus 결과 개수: {len(milvus_results)}")
            self.log(f"DEBUG - BM25 결과 개수: {len(bm25_results)}")
            
            if milvus_results:
                self.log(f"DEBUG - Milvus 첫 번째 결과 샘플: {milvus_results[0]}")
            if bm25_results:
                self.log(f"DEBUG - BM25 첫 번째 결과 샘플: {bm25_results[0]}")
            
            if not milvus_results and not bm25_results:
                return Message(text="검색 결과가 없습니다")
            
            # 3. 문서별 점수 매핑 (text를 키로 사용)
            doc_scores = {}
            
            # Milvus 점수 처리 (거리 기반이므로 낮을수록 좋음 -> 역수 사용)
            if milvus_results:
                milvus_scores = [1.0 / (1.0 + r.get('similarity_score', 1.0)) for r in milvus_results]
                normalized_milvus = self.normalize_scores(milvus_scores)
                
                for i, result in enumerate(milvus_results):
                    text = result.get('text', '')
                    if text:
                        doc_scores[text] = {
                            'text': text,
                            'id': result.get('id'),
                            'milvus_score': normalized_milvus[i],
                            'bm25_score': 0.0,
                            'similarity_score': result.get('similarity_score', 0),
                        }
            
            # BM25 점수 처리 (높을수록 좋음)
            if bm25_results:
                bm25_scores = [r.get('score', 0.0) for r in bm25_results]
                normalized_bm25 = self.normalize_scores(bm25_scores)
                
                for i, result in enumerate(bm25_results):
                    text = result.get('text', '')
                    if text:
                        if text in doc_scores:
                            doc_scores[text]['bm25_score'] = normalized_bm25[i]
                            doc_scores[text]['bm25_raw_score'] = bm25_scores[i]
                        else:
                            doc_scores[text] = {
                                'text': text,
                                'id': result.get('id'),
                                'milvus_score': 0.0,
                                'bm25_score': normalized_bm25[i],
                                'bm25_raw_score': bm25_scores[i],
                            }
            
            # 4. 최종 점수 계산 (가중 합)
            milvus_weight = self.milvus_weight if hasattr(self, 'milvus_weight') else 0.5
            bm25_weight = self.bm25_weight if hasattr(self, 'bm25_weight') else 0.5
            
            # 겹치는 문서 개수 확인
            both_found = sum(1 for scores in doc_scores.values() if scores['milvus_score'] > 0 and scores['bm25_score'] > 0)
            only_milvus = sum(1 for scores in doc_scores.values() if scores['milvus_score'] > 0 and scores['bm25_score'] == 0)
            only_bm25 = sum(1 for scores in doc_scores.values() if scores['milvus_score'] == 0 and scores['bm25_score'] > 0)
            
            self.log(f"DEBUG - 두 검색 모두에서 발견: {both_found}개")
            self.log(f"DEBUG - Milvus에만 있음: {only_milvus}개")
            self.log(f"DEBUG - BM25에만 있음: {only_bm25}개")
            
            for text, scores in doc_scores.items():
                scores['final_score'] = (
                    scores['milvus_score'] * milvus_weight + 
                    scores['bm25_score'] * bm25_weight
                )
            
            # 5. 최종 점수로 정렬
            sorted_results = sorted(
                doc_scores.values(), 
                key=lambda x: x['final_score'], 
                reverse=True
            )
            
            # 6. 결과 포맷팅
            result_text = f"Hybrid Search Results (총 {len(sorted_results)}개)\n"
            result_text += f"Milvus 가중치: {milvus_weight}, BM25 가중치: {bm25_weight}\n\n"
            
            for idx, result in enumerate(sorted_results, 1):
                result_text += f"[{idx}] Final Score: {result['final_score']:.4f}\n"
                result_text += f"  Milvus: {result['milvus_score']:.4f} | BM25: {result['bm25_score']:.4f}\n"
                
                if 'similarity_score' in result:
                    result_text += f"  원본 유사도: {result['similarity_score']:.4f}\n"
                if 'bm25_raw_score' in result:
                    result_text += f"  원본 BM25: {result['bm25_raw_score']:.4f}\n"
                
                if result.get('id'):
                    result_text += f"  ID: {result['id']}\n"
                
                text_preview = result['text'][:200] + '...' if len(result['text']) > 200 else result['text']
                result_text += f"  Text: {text_preview}\n\n"
            
            self.log(f"하이브리드 검색 완료: {len(sorted_results)}개 결과")
            
            return Message(text=result_text)
            
        except Exception as e:
            error_msg = f"오류 발생: {str(e)}"
            self.log(error_msg)
            import traceback
            self.log(f"상세 오류: {traceback.format_exc()}")
            return Message(text=error_msg)

    def build(self) -> Message:
        """빌드 메서드"""
        return self.fuse_results()

