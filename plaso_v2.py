import subprocess

try:
    # psort.exe 실행 명령어
    subprocess.run([
        r"C:\Users\rkddk\AppData\Local\Programs\Python\Python311\Scripts\psort.exe",
        "-o", "L2tcsv",                              # 출력 형식
        "-w", r"D:\luu\timeline.csv",                # 결과 CSV 경로
        "--output_time_zone", "Asia/Seoul",          # 타임존 설정 (수정됨)
        r"D:\luu\timeline.plaso"                     # 입력 .plaso 파일
    ], check=True)

    print("✅ 타임라인 CSV 생성이 완료되었습니다!")

except subprocess.CalledProcessError as e:
    print(f"❌ psort 실행 중 오류 발생: {e}")
except FileNotFoundError:
    print("❌ psort.exe 파일을 찾을 수 없습니다. Plaso가 올바르게 설치되어 있는지 확인하세요.")
except Exception as e:
    print(f"⚠️ 예상치 못한 오류 발생: {e}")
