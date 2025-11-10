import os
import pandas as pd
import re

# === 경로 설정 ===
input_dir = r"D:\foresic_project\TAG_TEST_CSV\artifact_csv"
output_dir = r"D:\foresic_project\TAG_TEST_CSV\filnish_tag"

# 출력 폴더 없으면 생성
os.makedirs(output_dir, exist_ok=True)

# === 규칙 사전 ===
# 파일명 패턴 → Tag
tag_rules = {
    "BasicSystemInfo": "system",
    # 나중에 다른 규칙도 쉽게 추가 가능
}

# === 함수 정의 ===
def add_tag_to_csv(file_path):
    filename = os.path.basename(file_path)

    # 파일명에 포함된 키워드로 태그 결정
    tag_value = None
    for key, tag in tag_rules.items():
        if key in filename:
            tag_value = tag
            break

    if not tag_value:
        print(f"⚠️ {filename}: 태그 규칙이 없어 건너뜀")
        return

    # CSV 읽기
    df = pd.read_csv(file_path, dtype=str).fillna("")

    # tag 컬럼 추가
    df["tag"] = tag_value

    # 출력 파일명 설정
    output_file = re.sub(r"\.csv$", "_tagged.csv", filename)
    output_path = os.path.join(output_dir, output_file)

    # 저장 (UTF-8-SIG로 BOM 포함)
    df.to_csv(output_path, index=False, encoding="utf-8-sig")

    print(f"✅ Tag 추가 완료 → {output_path} (tag='{tag_value}')")

# === 실행 ===
for file in os.listdir(input_dir):
    if file.endswith("_RECmd_Batch_BasicSystemInfo_Output.csv"):
        add_tag_to_csv(os.path.join(input_dir, file))
