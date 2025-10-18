from langflow.base.vectorstores.model import LCVectorStoreComponent, check_cached_vector_store
from langflow.helpers.data import docs_to_data
from langflow.io import (
    BoolInput,
    DictInput,
    DropdownInput,
    FloatInput,
    HandleInput,
    IntInput,
    SecretStrInput,
    StrInput,
)
from langflow.schema.data import Data


class MilvusVectorStoreComponent(LCVectorStoreComponent):
    """Milvus vector store with search capabilities."""

    display_name: str = "Milvus"
    description: str = "Milvus vector store with search capabilities"
    name = "Milvus"
    icon = "Milvus"

    inputs = [
        StrInput(name="collection_name", display_name="Collection Name", value="langflow"),
        StrInput(name="collection_description", display_name="Collection Description", value=""),
        StrInput(
            name="uri",
            display_name="Connection URI",
            value="http://localhost:19530",
        ),
        SecretStrInput(
            name="password",
            display_name="Milvus Token",
            value="",
            info="Ignore this field if no token is required to make connection.",
        ),
        DictInput(name="connection_args", display_name="Other Connection Arguments", advanced=True),
        StrInput(name="primary_field", display_name="Primary Field Name", value="pk"),
        StrInput(name="text_field", display_name="Text Field Name", value="text"),
        StrInput(name="vector_field", display_name="Vector Field Name", value="vector"),
        DropdownInput(
            name="consistency_level",
            display_name="Consistencey Level",
            options=["Bounded", "Session", "Strong", "Eventual"],
            value="Session",
            advanced=True,
        ),
        DictInput(name="index_params", display_name="Index Parameters", advanced=True),
        DictInput(name="search_params", display_name="Search Parameters", advanced=True),
        BoolInput(name="drop_old", display_name="Drop Old Collection", value=False, advanced=True),
        FloatInput(name="timeout", display_name="Timeout", advanced=True),
        *LCVectorStoreComponent.inputs,
        HandleInput(name="embedding", display_name="Embedding", input_types=["Embeddings"]),
        IntInput(
            name="number_of_results",
            display_name="Number of Results",
            info="Number of results to return.",
            value=4,
            advanced=True,
        ),
    ]

    @check_cached_vector_store
    def build_vector_store(self):
        print("\n--- Milvus LOG 1: build_vector_store 함수 시작 ---")
        
        try:
            from langchain_milvus.vectorstores import Milvus as LangchainMilvus
        except ImportError as e:
            msg = "Could not import Milvus integration package. Please install it with `pip install langchain-milvus`."
            raise ImportError(msg) from e

        self.connection_args.update(uri=self.uri, token=self.password)
    
        milvus_store = LangchainMilvus(
            embedding_function=self.embedding,
            collection_name=self.collection_name,
            collection_description=self.collection_description,
            connection_args=self.connection_args,
            consistency_level=self.consistency_level,
            index_params=self.index_params,
            search_params=self.search_params,
            drop_old=self.drop_old,
            auto_id=True,
            primary_field=self.primary_field,
            text_field=self.text_field,
            vector_field=self.vector_field,
          
        )

        self.ingest_data = self._prepare_ingest_data()

        documents = []
        for _input in self.ingest_data or []:
            if isinstance(_input, Data):
                documents.append(_input.to_lc_document())
            else:
                documents.append(_input)

        print(f"--- Milvus LOG 2: 입력으로부터 {len(documents)}개의 문서를 받았습니다.")
        
        print("--- Milvus LOG 3: 필터링 전 각 문서의 내용:")
        for i, doc in enumerate(documents):
            content = getattr(doc, 'page_content', 'NO_PAGE_CONTENT_ATTRIBUTE_ERROR')
            print(f"  - 문서 #{i}: '{content}'")

        if documents:
            filtered_documents = [
                doc for doc in documents
                if hasattr(doc, "page_content")
                and doc.page_content
                and doc.page_content.strip()
            ]
            
            print(f"--- Milvus LOG 4: 빈 문서 필터링 후 {len(filtered_documents)}개가 남았습니다.")

            if not filtered_documents:
                print("--- Milvus LOG 5: 유효한 문서가 없어 저장을 중단합니다.")
            else:
                try:
                    texts_to_embed = [doc.page_content for doc in filtered_documents]
                    print(f"--- Milvus LOG 7.1: 임베딩 모델에 {len(texts_to_embed)}개의 텍스트를 전달합니다.")

                    print("--- Milvus LOG 7.2: 임베딩 모델을 호출하여 벡터 변환을 시작합니다...")
                    
                    # milvus_store.embedding_function -> self.embedding 으로 수정됨
                    embeddings = self.embedding.embed_documents(texts_to_embed)

                    print(f"--- Milvus LOG 7.3: 임베딩 모델이 {len(embeddings)}개의 벡터를 반환했습니다.")

                    if len(texts_to_embed) != len(embeddings):
                        print(f"--- Milvus LOG 7.4 FATAL: 텍스트 개수({len(texts_to_embed)})와 벡터 개수({len(embeddings)})가 일치하지 않아 저장할 수 없습니다!")
                        raise ValueError(f"Mismatched lengths: {len(texts_to_embed)} texts vs {len(embeddings)} embeddings")

                    print("--- Milvus LOG 7.4: 텍스트와 벡터 개수가 일치합니다. Milvus에 저장을 시작합니다...")
                    milvus_store.add_embeddings(texts=texts_to_embed, embeddings=embeddings)
                    print("--- Milvus LOG 7.5: 문서 추가에 성공했습니다.")
                    
                except Exception as e:
                    print(f"--- Milvus LOG 8: 작업 중 에러 발생: {e}")
                    raise e

        return milvus_store

    def search_documents(self) -> list[Data]:
        vector_store = self.build_vector_store()

        if self.search_query and isinstance(self.search_query, str) and self.search_query.strip():
            docs_with_scores = vector_store.similarity_search_with_score(
                query=self.search_query,
                k=self.number_of_results,
            )

            # 문서만 추출하여 Data로 변환
            docs = [doc for doc, score in docs_with_scores]
            data = docs_to_data(docs)
            
            # 각 데이터에 유사도 점수 추가
            for i, (doc, score) in enumerate(docs_with_scores):
                if i < len(data):
                    data[i].data["similarity_score"] = float(score)
            
            self.status = data
            return data
        return []