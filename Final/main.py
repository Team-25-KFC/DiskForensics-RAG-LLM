#!/usr/bin/env python3
# -*- coding: utf-8 -*-
import importlib, subprocess, time, re, os
from pathlib import Path
from typing import List

# ── 기본값(환경변수로 덮어쓰기 가능) ─────────────────────────
AIM_EXE  = os.getenv("AIM_EXE",  r"C:\Arsenal-Image-Mounter-v3.11.307\aim_cli.exe")
E01_PATH = os.getenv("E01_PATH", r"H:\Laptop\Laptop.E01")
KAPE_EXE = os.getenv("KAPE_EXE", r"D:\KAPE\kape.exe")
BASE_OUT = Path(os.getenv("BASE_OUT", r"D:\Kape Output"))

MOUNT_STABILIZE_SEC = int(os.getenv("MOUNT_STABILIZE_SEC", "15"))
PS_TIMEOUT_SEC      = int(os.getenv("PS_TIMEOUT_SEC", "90"))
PROC_TIMEOUT_SEC    = int(os.getenv("PROC_TIMEOUT_SEC", "3600"))

BASE_OUT.mkdir(parents=True, exist_ok=True)

def run_ps(cmd: str, timeout: int | None = None):
    return subprocess.run(
        ["powershell", "-NoProfile", "-Command", cmd],
        capture_output=True, text=True, timeout=timeout
    )

def ps_lines(cp: subprocess.CompletedProcess):
    return [l.strip() for l in (cp.stdout or "").splitlines() if l.strip()]

def safe_run(func, *args, **kwargs):
    try:
        return func(*args, **kwargs)
    except SystemExit as se:
        print(f"[WARN] Caught SystemExit from child: {se}")
        return None
    except Exception as e:
        print(f"[ERR ] Exception in child: {e}")
        return None

# ── AIM helpers ───────────────────────────────────────────────────
def mount_e01():
    cmd = [AIM_EXE, "--mount", f"--filename={E01_PATH}", "--provider=LibEwf", "--readonly", "--online"]
    device_number = None
    disk_number = None
    try:
        proc = subprocess.Popen(cmd, stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True)
        start = time.time()
        assert proc.stdout
        for line in proc.stdout:
            line = line.strip()
            m_dev = re.search(r"Device number\s+(\d+)", line)
            if m_dev: device_number = m_dev.group(1)
            m_phy = re.search(r"Device is .*PhysicalDrive(\d+)", line, re.IGNORECASE)
            if m_phy: disk_number = int(m_phy.group(1))
            if "Mounted online" in line or "Mounted read only" in line: break
            if time.time() - start > 120: break
        time.sleep(MOUNT_STABILIZE_SEC)
        return disk_number, device_number
    except Exception as e:
        print(f"[ERR ] mount_e01 failed: {e}")
        return None, None

def get_ntfs_volumes(disk_number: int):
    ps = (f"Get-Partition -DiskNumber {disk_number} | Get-Volume | "
          f"Where-Object {{$_.FileSystem -eq 'NTFS'}} | Select-Object -ExpandProperty Path")
    r = run_ps(ps, timeout=PS_TIMEOUT_SEC)
    vols = ps_lines(r)
    return [p if p.endswith('\\') else p + '\\' for p in vols if p.startswith('\\\\?\\Volume{')]

def get_letter_for_volume(vol_path: str):
    r = run_ps(f"Get-Volume | Where-Object {{$_.Path -eq '{vol_path}'}} | "
               f"Select-Object -ExpandProperty DriveLetter", timeout=PS_TIMEOUT_SEC)
    letter = (r.stdout or "").strip()
    return f"{letter}:" if letter else None

def dismount_e01(device_number=None):
    cmd = [AIM_EXE, f"--dismount={device_number}"] if device_number else [AIM_EXE, "--dismount=all"]
    try:
        subprocess.run(cmd, check=True, capture_output=True)
        print("[INFO] Dismounted.")
    except Exception as e:
        print(f"[WARN] Dismount error ignored: {e}")

# ── 수동 체인 실행 ────────────────────────────────────────────────
def run_artifacts(letters: List[str], cfg: dict):
    artifacts = importlib.import_module("artifacts")
    if not hasattr(artifacts, "run"):
        print("[ERR] artifacts.py에 run(drive_letters, unmount_callback, cfg) 함수가 필요합니다.")
        return
    print("[STEP] Target copy (artifacts.py)")
    safe_run(artifacts.run, letters, (lambda: None), cfg)

def run_ntfs_modules(letters: List[str], cfg: dict):
    ntfs = importlib.import_module("ntfs")  # 파일명: ntfs.py
    if not hasattr(ntfs, "run"):
        print("[ERR] ntfs.py에 run(...) 함수가 필요합니다.")
        return
    print("[STEP] NTFS modules (ntfs.py)")
    try:
        # 신형: run(drive_letters, cfg)
        safe_run(ntfs.run, letters, cfg)
    except TypeError:
        # 구형: run(drive_letters, unmount_callback, cfg)
        safe_run(ntfs.run, letters, (lambda: None), cfg)

# ── main ──────────────────────────────────────────────────────────
def main():
    disk, dev = mount_e01()
    if disk is None:
        print("[ERR] AIM 마운트 실패")
        return

    try:
        vols = get_ntfs_volumes(disk)
        letters = [get_letter_for_volume(v) for v in vols]
        letters = [l for l in letters if l]
        print(f"[INFO] NTFS 드라이브: {', '.join(letters) if letters else '(없음)'}")
        if not letters:
            print("[ERR ] NTFS 드라이브가 없어 종료")
            return

        cfg = {
            "BASE_OUT": BASE_OUT,
            "KAPE_EXE": Path(KAPE_EXE),
            "PROC_TIMEOUT_SEC": PROC_TIMEOUT_SEC,
            # 필요하면 강제 재복사 옵션도 같이 넘길 수 있음
            # "FORCE_RECOPY": True,
        }

        run_artifacts(letters, cfg)
        run_ntfs_modules(letters, cfg)

    except Exception as e:
        print(f"[FATAL] main 실패: {e}")
    finally:
        dismount_e01(dev)

if __name__ == "__main__":
    main()
