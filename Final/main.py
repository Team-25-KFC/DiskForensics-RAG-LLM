#!/usr/bin/env python3
# -*- coding: utf-8 -*-
import importlib, subprocess, time, re, os, inspect
from pathlib import Path
from typing import List, Optional
from concurrent.futures import ThreadPoolExecutor, as_completed

# ── 기본값(환경변수로 덮어쓰기 가능) ─────────────────────────
AIM_EXE  = os.getenv("AIM_EXE",  r"C:\Arsenal-Image-Mounter-v3.11.307\aim_cli.exe")
E01_PATH = os.getenv("E01_PATH", r"H:\Laptop\Laptop.E01")
KAPE_EXE = os.getenv("KAPE_EXE", r"D:\KAPE\kape.exe")
BASE_OUT = Path(os.getenv("BASE_OUT", r"D:\Kape Output"))

MOUNT_STABILIZE_SEC = int(os.getenv("MOUNT_STABILIZE_SEC", "15"))
PS_TIMEOUT_SEC      = int(os.getenv("PS_TIMEOUT_SEC", "90"))
PROC_TIMEOUT_SEC    = int(os.getenv("PROC_TIMEOUT_SEC", "3600"))

# 병렬 실행 워커 수(기본 4). 예) PowerShell: set MODULE_MAX_WORKERS=6
MODULE_MAX_WORKERS = int(os.getenv("MODULE_MAX_WORKERS", "4"))

# 콤마 구분 모듈 목록 지정(없으면 DEFAULT_MODULES 사용). 예) set MODULES=ntfs,pecmd,lecmd
SELECTED_MODULES = [m.strip() for m in os.getenv("MODULES", "").split(",") if m.strip()]

BASE_OUT.mkdir(parents=True, exist_ok=True)

# ── 공용 실행 유틸 ───────────────────────────────────────────────
def run_ps(cmd: str, timeout: Optional[int] = None):
    return subprocess.run(["powershell", "-NoProfile", "-Command", cmd],
                          capture_output=True, text=True, timeout=timeout)

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
            if m_dev:
                device_number = m_dev.group(1)
            m_phy = re.search(r"Device is .*PhysicalDrive(\d+)", line, re.IGNORECASE)
            if m_phy:
                disk_number = int(m_phy.group(1))
            if "Mounted online" in line or "Mounted read only" in line:
                break
            if time.time() - start > 120:
                break
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
    r = run_ps(
        f"Get-Volume | Where-Object {{$_.Path -eq '{vol_path}'}} | "
        f"Select-Object -ExpandProperty DriveLetter",
        timeout=PS_TIMEOUT_SEC
    )
    letter = (r.stdout or "").strip()
    return f"{letter}:" if letter else None

def dismount_e01(device_number=None):
    cmd = [AIM_EXE, f"--dismount={device_number}"] if device_number else [AIM_EXE, "--dismount=all"]
    try:
        subprocess.run(cmd, check=True, capture_output=True)
        print("[INFO] Dismounted.")
    except Exception as e:
        print(f"[WARN] Dismount error ignored: {e}")

# ── Target 복사(artifacts.py) ─────────────────────────────────────
def run_artifacts(letters: List[str], cfg: dict):
    artifacts = importlib.import_module("artifacts")
    if not hasattr(artifacts, "run"):
        print("[ERR] artifacts.py에 run(drive_letters, unmount_callback, cfg) 함수가 필요합니다.")
        return
    print("[STEP] Target copy (artifacts.py)")
    safe_run(artifacts.run, letters, (lambda: None), cfg)

# ── 모듈 시그니처 자동 감지 실행기 ───────────────────────────────
def _call_module_run(mod, letters: List[str], cfg: dict, name: str):
    # 지원 시그니처: run(drive_letters, cfg) / run(drive_letters, unmount, cfg) / run(cfg) / run()
    if not hasattr(mod, "run"):
        print(f"[SKIP] {name}: run() 미구현")
        return

    fn = mod.run
    try:
        sig = inspect.signature(fn)
    except Exception:
        sig = None

    try:
        if sig:
            params = list(sig.parameters.keys())
            if len(params) >= 2 and params[0] != 'cfg':
                try:
                    fn(letters, cfg)
                except TypeError:
                    fn(letters, (lambda: None), cfg)
            elif len(params) >= 1 and params[0] == 'cfg':
                fn(cfg)
            else:
                fn()
        else:
            try:
                fn(letters, cfg)
            except TypeError:
                try:
                    fn(letters, (lambda: None), cfg)
                except TypeError:
                    try:
                        fn(cfg)
                    except TypeError:
                        fn()
        print(f"[DONE] {name}")
    except SystemExit as se:
        print(f"[WARN] {name} raised SystemExit: {se}")
    except Exception as e:
        print(f"[ERR ] {name} 실행 오류: {e}")

# ── 논리 모듈명 → 실제 import 후보 매핑 ─────────────────────────
# 'ntfs' 라고 지정하면 ntfs.py 우선, 없으면 ntfs_modules.py를 시도
MODULE_IMPORT_MAP = {
    "ntfs": ["ntfs", "ntfs_modules"],
    # 나머지는 이름 그대로 import 시도
}

def _import_by_logical_name(name: str):
    candidates = MODULE_IMPORT_MAP.get(name, [name])
    last_err = None
    for cand in candidates:
        try:
            return importlib.import_module(cand), cand
        except ImportError as e:
            last_err = e
            continue
    raise ImportError(last_err or f"Cannot import {name}")

# ── 모듈 병렬 실행(artifacts 후, 전부 동급 병렬) ─────────────────
def run_tool_modules(letters: List[str], cfg: dict, module_names: List[str]):
    results = {}

    def _runner(logical_name: str):
        try:
            mod, real_name = _import_by_logical_name(logical_name)
        except ImportError as e:
            return (logical_name, f"[MISS] {logical_name}.py import 실패: {e}")
        buf = [f"[STEP] {logical_name} (import: {real_name}).py"]
        try:
            _call_module_run(mod, letters, cfg, logical_name)
            buf.append(f"[DONE] {logical_name}")
        except Exception as e:
            buf.append(f"[ERR ] {logical_name} 실행 오류: {e}")
        return (logical_name, "\n".join(buf))

    with ThreadPoolExecutor(max_workers=MODULE_MAX_WORKERS) as ex:
        futs = {ex.submit(_runner, n): n for n in module_names}
        for fut in as_completed(futs):
            name, out = fut.result()
            results[name] = out

    # 요청 순서대로 출력
    for n in module_names:
        if n in results:
            print(results[n])

# ── 실행 목록(artifacts 제외, 전부 동급) ─────────────────────────
# 파일명(.py 제외) 기준. 'ntfs'는 ntfs.py 우선, 없으면 ntfs_modules.py 대체.
DEFAULT_MODULES = [
    "ntfs",             # (논리명) ntfs or ntfs_modules
    "pecmd",            # Prefetch → PECmd
    "amcache",          # Amcache → AmcacheParser
    "appcompatcache",   # ShimCache → AppCompatCacheParser
    "lecmd", "jlecmd",  # LNK / JumpLists
    "rbcmd",            # Recycle Bin
    "SrumECmd",             # SRUM
    "sqlecmd", 
    "sbecmd",           # Browser
    "wxtcmd",           # Windows Timeline
    "eventlog",         # Event Logs
    "registry",         # RECmd batch
]

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
        }

        # 1) Target 복사(artifacts.py만 개별화/선행)
        run_artifacts(letters, cfg)

        # 2) 나머지 모듈: 전부 동급으로 병렬 실행 (여기에 ntfs 포함)
        module_set = SELECTED_MODULES if SELECTED_MODULES else DEFAULT_MODULES
        print(f"[INFO] Modules 실행(병렬 {MODULE_MAX_WORKERS}): {', '.join(module_set)}")
        run_tool_modules(letters, cfg, module_set)

    except Exception as e:
        print(f"[FATAL] main 실패: {e}")
    finally:
        dismount_e01(dev)

if __name__ == "__main__":
    main()
