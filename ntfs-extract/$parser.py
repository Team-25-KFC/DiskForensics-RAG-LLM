#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
parser_split_i30_v2.py — (2025-10-28)
NTFS 메타데이터 자동 추출 (E01 → AIM mount → MFTECmd → CSV)
개선 내용:
 - 드라이브별 폴더에 분리 저장 (병합 없음)
 - $I30 병렬 추출 (4스레드)
 - 경로 필터링 및 대용량 스킵(>10MB)
 - $MFT, $Boot, $SDS, $UsnJrnl 기본 추출 동일 유지
환경: Windows 10/11, 관리자 권장
"""

import os, sys, time, re, subprocess
from pathlib import Path
from concurrent.futures import ThreadPoolExecutor, as_completed

# -----------------------------
# 사용자 설정
# -----------------------------
E01_PATH   = r"H:\Laptop\Laptop.E01"
AIM_EXE    = r"C:\Arsenal-Image-Mounter-v3.11.307\aim_cli.exe"
MFTE_EXE   = r"C:\eztools\MFTECmd.exe"
OUTPUT_DIR = r"C:\eztools\result_ntfs"
os.makedirs(OUTPUT_DIR, exist_ok=True)

MOUNT_STABILIZE_SEC = 5
MFTE_RETRIES = 2
MFTE_RETRY_BACKOFF = 2

# -----------------------------
# PowerShell & subprocess util
# -----------------------------
def run_ps(cmd):
    return subprocess.run(["powershell", "-NoProfile", "-Command", cmd], capture_output=True, text=True)

def ps_lines(cp):
    return [l.strip() for l in (cp.stdout or "").splitlines() if l.strip()]

def safe_run(cmd, capture=True, timeout=None):
    try:
        if capture:
            res = subprocess.run(cmd, capture_output=True, text=True, timeout=timeout)
        else:
            res = subprocess.run(cmd, timeout=timeout)
        return res
    except Exception as e:
        class _R: pass
        r = _R()
        r.returncode = 1
        r.stdout = ""
        r.stderr = str(e)
        return r

# -----------------------------
# AIM mount / dismount
# -----------------------------
def mount_e01():
    print("[ACTION] Mounting E01 image...")
    cmd = [AIM_EXE, "--mount", f"--filename={E01_PATH}", "--provider=LibEwf", "--readonly", "--online"]
    device_number = None
    disk_number = None
    try:
        proc = subprocess.Popen(cmd, stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True)
        start = time.time()
        while True:
            line = proc.stdout.readline()
            if not line:
                break
            line = line.strip()
            print("[AIM] " + line)
            m_dev = re.search(r"Device number\s+(\d+)", line)
            if m_dev:
                device_number = m_dev.group(1)
            m_phy = re.search(r"Device is .*PhysicalDrive(\d+)", line, re.IGNORECASE)
            if m_phy:
                disk_number = int(m_phy.group(1))
            if ("Mounted read only" in line) or ("Mounted online" in line):
                break
            if time.time() - start > 120:
                print("[WARN] AIM output parse timeout")
                break
        print(f"[INFO] Device: {device_number}, PhysicalDrive: {disk_number}")
        print(f"[INFO] Waiting {MOUNT_STABILIZE_SEC}s for Windows to recognize volumes...")
        time.sleep(MOUNT_STABILIZE_SEC)
        return disk_number, device_number
    except Exception as e:
        print(f"[ERROR] Mount failed: {e}")
        return None, None

def dismount_e01(device_number=None):
    print("[ACTION] Dismounting virtual disk...")
    if device_number:
        cmd = [AIM_EXE, f"--dismount={device_number}"]
    else:
        cmd = [AIM_EXE, "--dismount=all"]
    try:
        subprocess.run(cmd, check=True)
        print("[INFO] Dismount complete.")
    except Exception as e:
        print(f"[ERROR] Dismount failed: {e}")

# -----------------------------
# NTFS Volume util
# -----------------------------
def get_ntfs_volumes(disk_number):
    ps = (f"Get-Partition -DiskNumber {disk_number} | Get-Volume | "
          f"Where-Object {{$_.FileSystem -eq 'NTFS'}} | Select-Object -ExpandProperty Path")
    r = run_ps(ps)
    vols = ps_lines(r)
    guids = [p if p.endswith("\\") else p + "\\" for p in vols if p.startswith("\\\\?\\Volume{")]
    print(f"[INFO] NTFS volumes found: {len(guids)}")
    return guids

def get_letter_for_volume(vol_path):
    ps = f"Get-Volume | Where-Object {{$_.Path -eq '{vol_path}'}} | Select-Object -ExpandProperty DriveLetter"
    r = run_ps(ps)
    letter = (r.stdout or "").strip()
    if letter:
        return f"{letter}:"
    return None

# -----------------------------
# MFTECmd retry wrapper
# -----------------------------
def run_mfte_with_retries(cmd_args, retries=MFTE_RETRIES):
    attempt = 0
    while attempt <= retries:
        attempt += 1
        print(f"[IN-PROGRESS] MFTECmd (attempt {attempt}/{retries+1}) -> {' '.join(cmd_args)}")
        res = safe_run(cmd_args, capture=True, timeout=None)  
        out = (res.stdout or "") + (res.stderr or "")
        rc = getattr(res, "returncode", 1)
        if rc == 0:
            print("[OK] MFTECmd succeeded")
            return True, out
        else:
            print(f"[WARN] MFTECmd failed rc={rc}. tail:\n{out.strip()[-300:]}")
            if attempt <= retries:
                time.sleep(MFTE_RETRY_BACKOFF * attempt)
    return False, out

# -----------------------------
# Volume processing
# -----------------------------
def process_volume(vol_path):
    letter = get_letter_for_volume(vol_path)
    drive_letter = letter[0] if letter else "VOL"
    drive_folder = os.path.join(OUTPUT_DIR, drive_letter)
    os.makedirs(drive_folder, exist_ok=True)

    print(f"[START] Processing {vol_path} (drive={drive_letter})")

    base = f"{letter}\\" if letter else vol_path
    mft_src = f"{base}$MFT"
    boot_src = f"{base}$Boot"
    sds_src = f"{base}$Secure:$SDS"
    j_src = f"{base}$Extend\\$UsnJrnl:$J"

    # 1) $MFT
    out_mft = os.path.join(drive_folder, f"MFT_{drive_letter}.csv")
    ok, _ = run_mfte_with_retries([MFTE_EXE, "-f", mft_src, "--csv", drive_folder, "--csvf", os.path.basename(out_mft)])
    if not ok: print("[WARN] $MFT failed")

    # 2) $Boot
    out_boot = os.path.join(drive_folder, f"Boot_{drive_letter}.csv")
    ok, _ = run_mfte_with_retries([MFTE_EXE, "-f", boot_src, "--csv", drive_folder, "--csvf", os.path.basename(out_boot)])
    if not ok: print("[WARN] $Boot failed")

    # 3) $SDS
    out_sds = os.path.join(drive_folder, f"SDS_{drive_letter}.csv")
    ok, _ = run_mfte_with_retries([MFTE_EXE, "-f", sds_src, "--csv", drive_folder, "--csvf", os.path.basename(out_sds)], retries=1)
    if not ok: print("[WARN] $SDS failed")

    # 4) $UsnJrnl:$J
    out_j = os.path.join(drive_folder, f"UsnJrnl_J_{drive_letter}.csv")
    ok, _ = run_mfte_with_retries([MFTE_EXE, "-f", j_src, "-m", mft_src, "--csv", drive_folder, "--csvf", os.path.basename(out_j)], retries=1)
    if not ok: print("[WARN] $UsnJrnl failed")

    # 5) $I30
    print("[ACTION] Scanning for $I30 (optimized split mode)...")
    root = f"{letter}\\" if letter else vol_path
    scanned, found, skipped, large_skipped = 0, 0, 0, 0
    i30_folder = os.path.join(drive_folder, "I30")
    os.makedirs(i30_folder, exist_ok=True)

    EXCLUDE_DIRS = [
        "\\Windows\\assembly", "\\Windows\\WinSxS",
        "\\Windows\\Installer", "\\ProgramData", "\\$Recycle.Bin"
    ]
    LARGE_I30_THRESHOLD = 10_000_000
    MAX_WORKERS = 4

    i30_candidates = []
    for dirpath, dirnames, filenames in os.walk(root, followlinks=False):
        scanned += 1
        if any(ex.lower() in dirpath.lower() for ex in EXCLUDE_DIRS):
            skipped += 1
            continue
        i30_src = os.path.join(dirpath, "$I30")
        if not os.path.exists(i30_src):
            continue
        try:
            size = os.path.getsize(i30_src)
            if size > LARGE_I30_THRESHOLD:
                print(f"[SKIP-LARGE] {i30_src} ({size/1024/1024:.1f}MB)")
                large_skipped += 1
                continue
        except Exception:
            pass
        i30_candidates.append(i30_src)

    print(f"[INFO] I30 scan ready. Candidates={len(i30_candidates)}, SkippedDirs={skipped}, LargeFiles={large_skipped}")

    def extract_i30(i30_src, idx):
        out_name = f"I30_{idx:05d}.csv"
        ok, out = run_mfte_with_retries(
            [MFTE_EXE, "-f", i30_src, "--csv", i30_folder, "--csvf", out_name],
            retries=1
        )
        return (i30_src, ok)

    print(f"[ACTION] Parallel extracting {len(i30_candidates)} I30s with {MAX_WORKERS} threads...")
    with ThreadPoolExecutor(max_workers=MAX_WORKERS) as executor:
        futures = {executor.submit(extract_i30, src, i+1): src for i, src in enumerate(i30_candidates)}
        for i, f in enumerate(as_completed(futures)):
            src = futures[f]
            try:
                i30_src, ok = f.result()
                if ok:
                    found += 1
                    if found % 50 == 0:
                        print(f"[PROGRESS] Extracted {found}/{len(i30_candidates)} I30s...")
                else:
                    print(f"[FAIL] I30 extract failed: {i30_src}")
            except Exception as e:
                print(f"[ERROR] Exception while processing {src}: {e}")

    print(f"[DONE] I30 complete — total={len(i30_candidates)}, ok={found}, large_skipped={large_skipped}, skipped_dirs={skipped}")
    print(f"[COMPLETE] Volume {vol_path} done. Folder: {drive_folder}\n")
    return drive_folder

# -----------------------------
# MAIN
# -----------------------------
def main():
    if not os.path.exists(E01_PATH):
        print(f"[ERROR] E01 not found: {E01_PATH}")
        sys.exit(1)

    disk, dev = mount_e01()
    if disk is None:
        print("[ERROR] Mount failed. Exiting.")
        sys.exit(1)

    vols = get_ntfs_volumes(disk)
    if not vols:
        print("[ERROR] No NTFS volumes found. Dismounting and exit.")
        dismount_e01(dev)
        sys.exit(1)

    all_folders = []
    for vol in vols:
        letter = get_letter_for_volume(vol)
        print(f"[PLAN] Volume: {vol} -> letter={letter}")
        out_folder = process_volume(vol)
        all_folders.append(out_folder)

    dismount_e01(dev)
    print("\n[SUMMARY] Processed volumes:")
    for f in all_folders:
        print(f" - {f}")
    print("[FIN] NTFS extraction complete.")

if __name__ == "__main__":
    main()
