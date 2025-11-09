#!/usr/bin/env python3
# -*- coding: utf-8 -*-
import importlib, subprocess, time, re, os
from pathlib import Path
from typing import List

# ── 기본값(필요하면 환경변수로 덮어쓰기 가능) ─────────────────────────
AIM_EXE  = os.getenv("AIM_EXE",  r"C:\Arsenal-Image-Mounter-v3.11.307\aim_cli.exe")
E01_PATH = os.getenv("E01_PATH", r"H:\Laptop\Laptop.E01")
KAPE_EXE = os.getenv("KAPE_EXE", r"D:\KAPE\kape.exe")
BASE_OUT = Path(os.getenv("BASE_OUT", r"D:\Kape Output"))

MOUNT_STABILIZE_SEC = int(os.getenv("MOUNT_STABILIZE_SEC", "15"))
PS_TIMEOUT_SEC      = int(os.getenv("PS_TIMEOUT_SEC", "90"))
PROC_TIMEOUT_SEC    = int(os.getenv("PROC_TIMEOUT_SEC", "3600"))

BASE_OUT.mkdir(parents=True, exist_ok=True)

# ── PowerShell helpers ─────────────────────────────────────────────
def run_ps(cmd: str, timeout: int | None = None):
    return subprocess.run(
        ["powershell", "-NoProfile", "-Command", cmd],
        capture_output=True, text=True, timeout=timeout
    )

def ps_lines(cp: subprocess.CompletedProcess):
    return [l.strip() for l in (cp.stdout or "").splitlines() if l.strip()]

# ── AIM mount helpers ──────────────────────────────────────────────
def mount_e01():
    """AIM 가상 마운트: (disk_number, device_number) 반환."""
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
    except Exception:
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
    except Exception:
        pass

# ── main ──────────────────────────────────────────────────────────
def main():
    # 1) 마운트
    disk, dev = mount_e01()
    if disk is None:
        print("[ERR] AIM 마운트 실패")
        return

    try:
        # 2) 드라이브 문자 확보
        vols = get_ntfs_volumes(disk)
        letters = [get_letter_for_volume(v) for v in vols]
        letters = [l for l in letters if l]
        print(f"[INFO] NTFS 드라이브: {', '.join(letters) if letters else '(없음)'}")

        # 3) artifacts.py 호출 (타겟만 복사 전용)
        artifacts = importlib.import_module("artifacts")
        if not hasattr(artifacts, "run"):
            print("[ERR] artifacts.py에 run(drive_letters, unmount_callback, cfg) 함수가 필요합니다.")
            return

        # settings 없이 필요한 값만 전달
        cfg = {
            "BASE_OUT": BASE_OUT,
            "KAPE_EXE": Path(KAPE_EXE),
            "PROC_TIMEOUT_SEC": PROC_TIMEOUT_SEC,
        }

        # artifacts가 언마운트를 수행했는지 반환 받음
        already_unmounted = artifacts.run(letters, lambda: dismount_e01(dev), cfg)

        if not already_unmounted:
            dismount_e01(dev)

    except Exception as e:
        print(f"[FATAL] main 실패: {e}")
        dismount_e01(dev)

if __name__ == "__main__":
    main()
