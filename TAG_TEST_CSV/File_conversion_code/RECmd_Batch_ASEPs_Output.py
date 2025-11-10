import os
import pandas as pd
import re

# === 경로 설정 ===
input_dir = r"D:\foresic_project\TAG_TEST_CSV\artifact_csv"
output_dir = r"D:\foresic_project\TAG_TEST_CSV\filnish_tag"

# 출력 폴더 없으면 생성
os.makedirs(output_dir, exist_ok=True)

# === ASEP 관련 파일 이름 키워드 목록 ===
asep_keywords = [
    "RegistryASEPs",
    "SoftwareASEPs",
    "SoftwareClassesASEPs",
    "SoftwareWoW6432ASEPs",
    "SystemASEPs"
]

# === Persistence 태그 추가 함수 ===
def add_persistence_tag(file_path):
    filename = os.path.basename(file_path)

    df = pd.read_csv(file_path, dtype=str).fillna("")
    df["tag"] = "Persistence"

    output_file = re.sub(r"\.csv$", "_tagged.csv", filename)
    output_path = os.path.join(output_dir, output_file)

    df.to_csv(output_path, index=False, encoding="utf-8-sig")
    print(f"✅ Persistence 태그 추가 완료: {output_path}")

# === 실행 ===
for file in os.listdir(input_dir):
    if file.endswith(".csv") and any(keyword in file for keyword in asep_keywords):
        add_persistence_tag(os.path.join(input_dir, file))
