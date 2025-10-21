import os
import subprocess
import sys
import time
import re

# ==============================
# ⚙️ 환경 설정 (Configuration)
# ==============================
BASE_DIR = os.path.dirname(os.path.abspath(__file__))

# 📁 분석 대상 E01 경로
E01_PATH = r"H:\Laptop\Laptop.E01"

# 🧰 도구 경로
AIM_EXE = r"C:\Arsenal-Image-Mounter-v3.11.307\aim_cli.exe"
MFTE_EXE = r"C:\eztools\MFTECmd.exe"

# 📂 출력 폴더
OUTPUT_DIR = r"C:\eztools\result_ntfs"
os.makedirs(OUTPUT_DIR, exist_ok=True)

# ==============================
# 🚀 E01 마운트
# ==============================
def mount_e01():
    print("🚀 Mounting E01 image...\n")

    cmd_mount = [
        AIM_EXE,
        "--mount",
        f"--filename={E01_PATH}",
        "--provider=LibEwf",
        "--readonly",
        "--online"
    ]

    try:
        process = subprocess.Popen(
            cmd_mount,
            stdout=subprocess.PIPE,
            stderr=subprocess.STDOUT,
            text=True
        )

        mounted_drives = []
        start_time = time.time()
        mount_ready = False

        while True:
            line = process.stdout.readline()
            if not line:
                break

            print(line.strip())

            # ✅ 드라이브 문자 감지
            match = re.search(r"Mounted at\s+([A-Z]):\\", line)
            if match:
                drive = f"{match.group(1)}:\\"
                if drive not in mounted_drives:
                    mounted_drives.append(drive)
                mount_ready = True

            # ✅ 마운트 완료 로그 감지 후에도 드라이브가 아직 없으면 대기
            if "Mounted read only" in line or "Virtual disk mounted" in line:
                print("🕐 Waiting briefly for volume letters to appear...")
                time.sleep(3)  # 추가 대기 (볼륨 연결 시간)
                if mounted_drives:
                    print("✅ Mount completed, terminating CLI process.")
                    process.terminate()
                    break

            # ✅ 안전 타임아웃 (15초)
            if time.time() - start_time > 15:
                print("⏰ Timeout reached. Forcing process termination.")
                process.terminate()
                break

        print(f"\n✅ Mounted drives detected: {mounted_drives}\n")
        return mounted_drives

    except Exception as e:
        print(f"❌ Mount failed: {e}")
        return []

# ==============================
# 📊 MFTECmd 실행
# ==============================
def run_mftecmd(drive):
    print(f"📂 Running MFTECmd for {drive} ...")

    mft_path = os.path.join(drive, "$MFT")
    if not os.path.exists(mft_path):
        print(f"⚠️ {mft_path} not found. Skipping.\n")
        return

    csv_file = os.path.join(OUTPUT_DIR, f"MFT_{drive[0]}.csv")
    
    cmd_mfte = [
        MFTE_EXE,
        "-f", f"\\\\.\\{drive[0]}:",   # ← 핵심 수정 부분
        "--csv", OUTPUT_DIR,
        "--csvf", os.path.basename(csv_file)
    ]

    try:
        subprocess.run(cmd_mfte, check=True)
        print(f"✅ MFT extracted to {csv_file}\n")
    except subprocess.CalledProcessError as e:
        print(f"❌ Error running MFTECmd: {e}\n")

# ==============================
# 🔧 언마운트
# ==============================
def dismount_e01():
    print("🧹 Dismounting virtual disk...\n")
    cmd_unmount = [AIM_EXE, "--dismount=000000"]

    try:
        subprocess.run(cmd_unmount, check=True)
        print("✅ Dismount complete.\n")
    except Exception as e:
        print(f"⚠️ Failed to dismount: {e}\n")

# ==============================
# 🧪 실행 파이프라인
# ==============================
if __name__ == "__main__":
    # 1️⃣ E01 존재 확인
    if not os.path.exists(E01_PATH):
        print(f"❌ E01 파일을 찾을 수 없습니다: {E01_PATH}")
        sys.exit(1)

    # 2️⃣ Arsenal Image Mounter로 마운트
    mounted_drives = mount_e01()
    if not mounted_drives:
        print("❌ No drives mounted. Exiting.")
        sys.exit(1)

    # 3️⃣ 각 볼륨별 MFT 추출
    for drive in mounted_drives:
        run_mftecmd(drive)

    # 4️⃣ 언마운트
    dismount_e01()

    print("🎉 All volumes processed successfully!")
