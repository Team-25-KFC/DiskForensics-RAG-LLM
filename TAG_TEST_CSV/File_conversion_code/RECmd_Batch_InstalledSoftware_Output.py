import os
import pandas as pd
import re

# === 경로 설정 ===
input_dir = r"D:\foresic_project\TAG_TEST_CSV\artifact_csv"
output_dir = r"D:\foresic_project\TAG_TEST_CSV\filnish_tag"

# 출력 폴더 없으면 생성
os.makedirs(output_dir, exist_ok=True)

# === 함수 정의 ===
def add_useractivity_tag(file_path):
    filename = os.path.basename(file_path)

    # CSV 읽기
    df = pd.read_csv(file_path, dtype=str).fillna("")

    # tag 컬럼 추가 또는 덮어쓰기
    df["tag"] = "UserActivity"

    # 출력 파일명 (_tagged.csv)
    output_file = re.sub(r"\.csv$", "_tagged.csv", filename)
    output_path = os.path.join(output_dir, output_file)

    # 저장 (UTF-8-SIG)
    df.to_csv(output_path, index=False, encoding="utf-8-sig")

    print(f"✅ UserActivity 태그 추가 완료: {output_path}")

# === 실행 ===
for file in os.listdir(input_dir):
    if file.endswith("_RECmd_Batch_InstalledSoftware_Output.csv"):
        add_useractivity_tag(os.path.join(input_dir, file))
