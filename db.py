import os
import gc
import time
import json
import logging
import pandas as pd
import psycopg2
from concurrent.futures import ThreadPoolExecutor, as_completed
from pymilvus import connections, Collection, CollectionSchema, FieldSchema, DataType, utility
from sentence_transformers import SentenceTransformer
from langflow.custom.custom_component.component import Component
from langflow.io import MessageTextInput, Output
from langflow.schema.data import Data


class ForensicMilvusEmbedder(Component):
    display_name = "Forensic Milvus Embedder (Unified)"
    description = "Embed all forensic DB tables (by tag) into a single Milvus collection."
    documentation = "https://docs.langflow.org/components-custom-components"
    icon = "database"
    name = "ForensicMilvusEmbedderUnified"

    inputs = [
        MessageTextInput(
            name="tags",
            display_name="Tags (comma-separated)",
            info="Tags detected by HyDE Tag Parser, e.g., 'System, UserActivity'",
            value="System",
            tool_mode=True,
        ),
        MessageTextInput(name="dbname", display_name="Database Name", value="rudrb", tool_mode=True),
        MessageTextInput(name="user", display_name="DB Username", value="rudrb", tool_mode=True),
        MessageTextInput(name="password", display_name="DB Password", value="rudrb123", tool_mode=True),
        MessageTextInput(name="host", display_name="DB Host", value="localhost", tool_mode=True),
        MessageTextInput(name="port", display_name="DB Port", value="5432", tool_mode=True),
        MessageTextInput(name="milvus_host", display_name="Milvus Host", value="localhost", tool_mode=True),
        MessageTextInput(name="milvus_port", display_name="Milvus Port", value="19530", tool_mode=True),
    ]

    outputs = [
        Output(display_name="Embedding Summary", name="output", method="run_embedder"),
    ]

    def run_embedder(self) -> Data:
        tags = [t.strip().lower() for t in self.tags.split(",") if t.strip()]
        if not tags:
            return Data(value="❌ No tags provided.")

        db_info = dict(
            dbname=self.dbname,
            user=self.user,
            password=self.password,
            host=self.host,
            port=self.port
        )

        log_messages = []
        start_total = time.time()
        DIM = 384
        BATCH_SIZE = 200
        THREADS = 5
        collection_name = "forensic_artifacts"

        # 1️⃣ Milvus 연결
        try:
            connections.connect("default", host=self.milvus_host, port=self.milvus_port)
            log_messages.append(f"✅ Connected to Milvus ({self.milvus_host}:{self.milvus_port})")
        except Exception as e:
            return Data(value=f"❌ Milvus 연결 실패: {e}")

        # 기존 콜렉션 제거
        if utility.has_collection(collection_name):
            utility.drop_collection(collection_name)

        # 2️⃣ 모델 로드
        try:
            model = SentenceTransformer("paraphrase-multilingual-MiniLM-L12-v2")
            log_messages.append("✅ Embedding model loaded (MiniLM-L12-v2)")
        except Exception as e:
            return Data(value=f"❌ 모델 로드 실패: {e}")

        # 3️⃣ Milvus 콜렉션 생성 (단일)
        try:
            fields = [
                FieldSchema(name="id", dtype=DataType.INT64, is_primary=True, auto_id=True),
                FieldSchema(name="vector", dtype=DataType.FLOAT_VECTOR, dim=DIM),
                FieldSchema(name="text", dtype=DataType.VARCHAR, max_length=65535),
                FieldSchema(name="tag", dtype=DataType.VARCHAR, max_length=50),
            ]
            schema = CollectionSchema(fields, description="Unified forensic artifacts")
            collection = Collection(name=collection_name, schema=schema)
            collection.create_index(
                field_name="vector",
                index_params={"metric_type": "IP", "index_type": "HNSW", "params": {"M": 8, "efConstruction": 64}}
            )
            log_messages.append(f"✅ Milvus collection '{collection_name}' created.")
        except Exception as e:
            return Data(value=f"❌ Milvus 콜렉션 생성 실패: {e}")

        # 4️⃣ PostgreSQL 연결
        try:
            conn = psycopg2.connect(**db_info)
            cur = conn.cursor()
            log_messages.append(f"✅ Connected to PostgreSQL ({self.dbname})")
        except Exception as e:
            return Data(value=f"❌ DB 연결 실패: {e}")

        # 5️⃣ 모든 태그 테이블 데이터를 하나로 임베딩
        def embed_table(table_name, tag_label):
            try:
                query = f'SELECT id, source, artifact_name, file_name, full_description, tag FROM "{table_name}"'
                df = pd.read_sql(query, conn)
                if df.empty:
                    return f"⚠️ {table_name}: 데이터 없음, 건너뜀."

                df["tag"] = tag_label
                df["text"] = df.astype(str).apply(
                    lambda row: " | ".join([f"{col}: {val}" for col, val in row.items()]),
                    axis=1
                )

                texts = df["text"].tolist()
                tags_col = df["tag"].tolist()

                # 배치 분할
                batches = [texts[i:i+BATCH_SIZE] for i in range(0, len(texts), BATCH_SIZE)]

                def process_batch(batch_id, text_list, tag_list):
                    try:
                        start = time.perf_counter()
                        vectors = model.encode(text_list, batch_size=32, convert_to_numpy=True, show_progress_bar=False)
                        collection.insert([vectors, text_list, tag_list])
                        collection.flush()
                        elapsed = time.perf_counter() - start
                        return f"✅ [{table_name}] Batch-{batch_id} ({len(text_list)} rows, {elapsed:.2f}s)"
                    except Exception as e:
                        return f"❌ [{table_name}] Batch-{batch_id} 오류: {e}"

                with ThreadPoolExecutor(max_workers=THREADS) as executor:
                    futures = [executor.submit(process_batch, i, batches[i], [tag_label]*len(batches[i])) for i in range(len(batches))]
                    for future in as_completed(futures):
                        log_messages.append(future.result())

                return f"🎯 {table_name}: {len(df)} rows inserted."
            except Exception as e:
                return f"❌ {table_name} 처리 실패: {e}"

        for tag in tags:
            table_name = tag.lower()
            result = embed_table(table_name, tag)
            log_messages.append(result)
            gc.collect()

        conn.close()
        collection.flush()
        elapsed = (time.time() - start_total) / 60
        log_messages.append(f"🏁 전체 완료 ({elapsed:.2f}분 소요)")
        log_messages.append(f"✅ 최종 엔티티 수: {collection.num_entities}")
        return Data(value="\n".join(log_messages))
