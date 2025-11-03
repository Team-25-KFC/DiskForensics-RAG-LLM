import subprocess
import time

# 경로 설정
E01_PATH = r"D:\luu\win10.E01"
PLASO_FILE = r"D:\luu\timeline.plaso"
CSV_FILE = r"D:\luu\timeline.csv"
TIMEZONE = "Asia/Seoul"

LOG2TIMELINE_EXE = r"C:\Users\rkddk\AppData\Local\Programs\Python\Python311\Scripts\log2timeline.exe"
PSORT_EXE = r"C:\Users\rkddk\AppData\Local\Programs\Python\Python311\Scripts\psort.exe"

start_time = time.time()
print("🚀 타임라인 생성 시작...")

# log2timeline 실행 (최신 플라소 방식)
subprocess.run([
    LOG2TIMELINE_EXE,
    "-z", TIMEZONE,
    "--storage_file", PLASO_FILE,
    E01_PATH
], check=True)

# psort 실행 (.plaso → CSV)
subprocess.run([
    PSORT_EXE,
    "-o", "L2tcsv",
    "-w", CSV_FILE,
    "--timezone", TIMEZONE,
    PLASO_FILE
], check=True)

end_time = time.time()
elapsed = end_time - start_time
minutes = int(elapsed // 60)
seconds = int(elapsed % 60)

print(f"\n✅ 타임라인 CSV 생성 완료: {CSV_FILE}")
print(f"⏱ 총 소요 시간: {minutes}분 {seconds}초")
