#!/usr/bin/env python3
# -*- coding: utf-8 -*-
import os, subprocess
from pathlib import Path
from typing import List

# 필요한 RECmd 모듈 세트 (CSV 출력)
RECMD_MODULES = ",".join([
    "RECmd_AllRegExecutablesFoundOrRun",
    "RECmd_BasicSystemInfo",
    "RECmd_BCDBootVolume",
    "RECmd_InstalledSoftware",
    "RECmd_Kroll",
    "RECmd_Batch_MC",
    "RECmd_RegistryASEPs",
    "RECmd_SoftwareASEPs",
    "RECmd_SoftwareClassesASEPs",
    "RECmd_SoftwareWow6432ASEPs",
    "RECmd_SystemASEPs",
    "RECmd_UserActivity",
    "RECmd_UserClassesASEPs",
])

def _artifacts_root(base_out: Path, drive_letter: str) -> Path:
    return base_out / drive_letter[0] / "Artifacts"

def _resolve_msource(artifacts_root: Path, drive_letter: str) -> Path:
    sub = artifacts_root / drive_letter[0]
    return sub if sub.exists() else artifacts_root

def _ensure_dirs(p: Path):
    p.mkdir(parents=True, exist_ok=True)
    return p

def _has_registry(msource: Path) -> bool:
    cfg = msource / "Windows" / "System32" / "config"
    if cfg.is_dir():
        for hive in ("SOFTWARE", "SYSTEM", "SAM", "SECURITY"):
            if (cfg / hive).exists():
                return True
    # 복사 과정에서 경로가 바뀐 경우도 대비: *.DAT, *.LOG1 등 힌트 탐색
    for p in msource.rglob("SOFTWARE"):
        return True
    for p in msource.rglob("SYSTEM"):
        return True
    return False

def _marker(base_out: Path, dl: str) -> Path:
    return base_out / dl[0] / ".modules_registry_csv_done"

def _run_recmd_set(kape_exe: Path, msource: Path, mdest: Path, timeout_sec: int, log_path: Path):
    cmd = [
        str(kape_exe),
        "--module", RECMD_MODULES,
        "--msource", str(msource),
        "--mdest",   str(mdest),
        "--mef",     "csv",
        "--vss",     "false",
    ]
    mdest.mkdir(parents=True, exist_ok=True)
    with open(log_path, "w", encoding="utf-8") as lf:
        lf.write("[CMD] " + " ".join(cmd) + "\n")
        proc = subprocess.Popen(cmd, stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True)
        for line in proc.stdout:
            print(line.strip()); lf.write(line)
        proc.wait(timeout=timeout_sec)

def run(drive_letters: List[str], unmount_callback, cfg: dict) -> bool:
    """
    cfg: {
      "BASE_OUT": Path,
      "KAPE_EXE": Path,
      "PROC_TIMEOUT_SEC": int
    }
    """
    BASE_OUT: Path = cfg["BASE_OUT"]
    KAPE_EXE:  Path = cfg["KAPE_EXE"]
    TIMEOUT:   int  = int(cfg["PROC_TIMEOUT_SEC"])

    try:
        for dl in drive_letters:
            mark = _marker(BASE_OUT, dl)
            if mark.exists():
                print(f"[SKIP] {dl} registry: 이미 CSV 모듈 처리 완료 ({mark})")
                continue

            artifacts_root = _artifacts_root(BASE_OUT, dl)
            if not artifacts_root.exists():
                print(f"[SKIP] {dl} registry: Artifacts 부재 → {artifacts_root}")
                continue

            msource = _resolve_msource(artifacts_root, dl)
            if not _has_registry(msource):
                print(f"[SKIP] {dl} registry: 레지스트리 하이브 없음 → {msource}")
                continue

            mdest = _ensure_dirs(BASE_OUT / dl[0] / "RECmd")
            logs  = _ensure_dirs(BASE_OUT / dl[0] / "Logs")
            log_path = logs / f"registry_{dl[0]}_module_runlog.txt"

            print(f"[RUN ] {dl} registry(csv): msource={msource} → mdest={mdest}")
            _run_recmd_set(KAPE_EXE, msource, mdest, TIMEOUT, log_path)
            try:
                mark.write_text("done", encoding="utf-8")
            except Exception:
                pass
            print(f"[OK  ] {dl} registry(csv): 완료 → {mdest}")

        return False  # 언마운트는 메인에서
    except Exception as e:
        print(f"[FATAL] registry 모듈 실행 실패: {e}")
        return False
