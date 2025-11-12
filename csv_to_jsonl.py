import os
import pandas as pd
import json
import re
from pathlib import Path

# === 경로 설정 ===
input_dir  = Path(os.path.expandvars(r"C:\Users\aromi\바탕 화면\langflow\lang_flow\fin_tag"))
output_dir = Path(os.path.expandvars(r"C:\Users\aromi\바탕 화면\langflow\lang_flow\data_jsonl"))
output_dir.mkdir(parents=True, exist_ok=True)

# === 공통 처리 함수 ===
def process_csv(file_path):
    df = pd.read_csv(file_path, dtype=str).fillna("")

    # 1️⃣ 삭제할 컬럼 제거
    drop_cols = ["HivePath", "HiveType", "Category"]  # ✅ Category 추가
    for col in drop_cols:
        if col in df.columns:
            df.drop(columns=[col], inplace=True)

    # 2️⃣ Type 컬럼 생성 (기존 Description을 복사하고 이름 변경)
    if "Description" in df.columns:
        df.rename(columns={"Description": "Type"}, inplace=True)

    # 3️⃣ description 컬럼 생성 (기존 남은 컬럼들을 | 로 이어붙임)
    keep_cols = {"Type", "LastWriteTimestamp", "tag"}
    desc_parts = []
    for col in df.columns:
        if col not in keep_cols:
            desc_parts.append(df[col].apply(lambda x, c=col: f"{c} : {x}" if x else ""))
    df["description"] = [" | ".join(filter(None, row)) for row in zip(*desc_parts)]

    # 4️⃣ 컬럼 순서 재정렬
    for c in ["Type", "LastWriteTimestamp", "description", "tag"]:
        if c not in df.columns:
            df[c] = ""
    df = df[["Type", "LastWriteTimestamp", "description", "tag"]]

    # 5️⃣ JSONL로 저장 (출력 경로 변경)
    base_name = os.path.splitext(os.path.basename(file_path))[0]
    output_path = os.path.join(output_dir, base_name + ".jsonl")

    with open(output_path, "w", encoding="utf-8") as f:
        for _, row in df.iterrows():
            json.dump(row.to_dict(), f, ensure_ascii=False)
            f.write("\n")

    print(f" 변환 완료: {output_path}")

# === 실행 ===
for file in os.listdir(input_dir):
    if file.endswith(".csv"):
        process_csv(os.path.join(input_dir, file))