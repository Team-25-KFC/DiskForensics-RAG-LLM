#!/usr/bin/env python3
# -*- coding: utf-8 -*-
r"""
ntfs_modules.py — NTFS 모듈 CSV 실행 워커 (E:\ 구조 우선)
- 입력: BASE_OUT\<Drive>\Artifacts  (우선)  /  BASE_OUT\$NFTS_<Drive>\Artifacts (보조)
- 출력: BASE_OUT\<Drive>\<모듈명>\*.csv, BASE_OUT\<Drive>\Logs\*.log
- INDXRipper: --msource는 드라이브 루트('E:\')
- MFTECmd_*, NTFSLogTracker_*: --msource는 복사본(Artifacts)
"""

import subprocess
from pathlib import Path
from typing import List

MODULES_9 = [
    "MFTECmd_$MFT",
    "MFTECmd_$J",
    "MFTECmd_$Boot",
    "MFTECmd_$MFT_FileListing",
    "MFTECmd_$MFT_ProcessMFTSlack",
    "MFTECmd_$MFT_DumpResidentFiles",
    "NTFSLogTracker_$J",
    "NTFSLogTracker_$LogFile",
    "INDXRipper",
]

MODULE_BIN_DIR = Path(r"C:\KAPE\Modules\bin")

# -----------------------------
# 경로 유틸 (E\Artifacts 우선)
# -----------------------------
def _artifact_root_candidates(base_out: Path, dl: str) -> list[Path]:
    # 1) BASE_OUT\E\Artifacts (우선)
    # 2) BASE_OUT\$NFTS_E\Artifacts (보조)
    return [
        base_out / dl[0] / "Artifacts",
        base_out / f"$NFTS_{dl[0]}" / "Artifacts",
    ]

def _artifact_root(base_out: Path, dl: str) -> Path | None:
    for p in _artifact_root_candidates(base_out, dl):
        if p.exists():
            return p
    return None

def _out_root_from_artifacts(artifacts: Path) -> Path:
    # 항상 아티팩트 폴더의 부모를 출력 루트로 사용 (E\)
    return artifacts.parent

def _logs_dir(out_root: Path) -> Path:
    d = out_root / "Logs"
    d.mkdir(parents=True, exist_ok=True)
    return d

# -----------------------------
# 실행 파일 점검
# -----------------------------
def _find_exe_anywhere_by_name(exe_name: str) -> Path | None:
    if not MODULE_BIN_DIR.exists():
        return None
    for p in MODULE_BIN_DIR.rglob("*.exe"):
        if p.name.lower() == exe_name.lower():
            return p
    return None

def _has_mftecmd() -> bool:
    return _find_exe_anywhere_by_name("MFTECmd.exe") is not None

def _has_indxripper() -> bool:
    return _find_exe_anywhere_by_name("INDXRipper.exe") is not None

def _has_ntfs_log_tracker_any_ver() -> bool:
    return _find_exe_anywhere_by_name("NTFS_Log_Tracker_CMD.exe") is not None

# -----------------------------
# KAPE 실행기
# -----------------------------
def _stream_kape(cmd: list[str], log_path: Path, timeout_sec: int) -> int:
    log_path.parent.mkdir(parents=True, exist_ok=True)
    with open(log_path, "w", encoding="utf-8") as lf:
        lf.write("[CMD] " + " ".join(cmd) + "\n")
        proc = subprocess.Popen(cmd, stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True)
        assert proc.stdout
        try:
            for line in proc.stdout:
                lf.write(line.rstrip() + "\n")
            return proc.wait(timeout=timeout_sec if timeout_sec > 0 else None)
        except subprocess.TimeoutExpired:
            proc.kill()
            lf.write("[ERROR] timeout\n")
            return -9

def _run_indxripper(letter: str, out_root: Path, kape_exe: Path, logs_dir: Path, timeout_sec: int):
    if not _has_indxripper():
        (logs_dir / "INDXRipper.skip.log").write_text("reason=INDXRipper.exe_not_found\n", encoding="utf-8")
        print(f"[SKIP] INDXRipper: exe not found")
        return

    mdest = out_root / "INDXRipper"
    cmd = [
        str(kape_exe),
        "--msource", f"{letter}\\",  # 드라이브 루트
        "--mdest",   str(mdest),
        "--module",  "INDXRipper",
        "--mef",     "csv",
        "--vss",     "false",
    ]
    print(f"[RUN ] INDXRipper ({letter}\\)")
    rc = _stream_kape(cmd, logs_dir / "INDXRipper.log", timeout_sec)
    if rc != 0:
        print(f"[FAIL] INDXRipper rc={rc}")
        try:
            if mdest.exists() and not any(mdest.iterdir()):
                mdest.rmdir()
        except Exception:
            pass
    else:
        print(f"[OK  ] INDXRipper")

def _run_generic_module(msource: Path, out_root: Path, module_name: str,
                        kape_exe: Path, logs_dir: Path, timeout_sec: int):
    base = module_name.split("_", 1)[0].lower()
    if base.startswith("mftecmd"):
        if not _has_mftecmd():
            (logs_dir / f"{module_name}.skip.log").write_text("reason=MFTECmd.exe_not_found\n", encoding="utf-8")
            print(f"[SKIP] {module_name}: MFTECmd.exe not found")
            return
    elif base.startswith("ntfslogtracker"):
        if not _has_ntfs_log_tracker_any_ver():
            (logs_dir / f"{module_name}.skip.log").write_text("reason=NTFS_Log_Tracker_CMD.exe_not_found\n", encoding="utf-8")
            print(f"[SKIP] {module_name}: NTFS_Log_Tracker_CMD.exe not found")
            return
        (logs_dir / f"{module_name}.warn.log").write_text(
            "note=.mkape may reference v1.8; ensure it matches installed version (e.g., v1.9)\n",
            encoding="utf-8"
        )

    mdest = out_root / module_name
    cmd = [
        str(kape_exe),
        "--msource", str(msource),
        "--mdest",   str(mdest),
        "--module",  module_name,
        "--mef",     "csv",
        "--vss",     "false",
    ]
    print(f"[RUN ] {module_name} (src={msource})")
    rc = _stream_kape(cmd, logs_dir / f"{module_name}.log", timeout_sec)
    if rc != 0:
        print(f"[FAIL] {module_name} rc={rc}")
        try:
            if mdest.exists() and not any(mdest.iterdir()):
                mdest.rmdir()
        except Exception:
            pass
    else:
        print(f"[OK  ] {module_name}")

# -----------------------------
# 엔트리포인트
# -----------------------------
def run(drive_letters: List[str], unmount_callback, cfg: dict) -> bool:
    """
    main.py에서 호출:
      - drive_letters: ['E:', 'I:', ...]
      - cfg: {"BASE_OUT": Path, "KAPE_EXE": Path, "PROC_TIMEOUT_SEC": int}
    반환: False (언마운트는 메인에서)
    """
    BASE_OUT: Path = cfg["BASE_OUT"]
    KAPE_EXE: Path  = cfg["KAPE_EXE"]
    TIMEOUT:  int   = int(cfg.get("PROC_TIMEOUT_SEC", 1800))

    for dl in drive_letters:
        artifacts = _artifact_root(BASE_OUT, dl)
        if not artifacts:
            print(f"[SKIP] {dl} ntfs-modules: Artifacts not found → {_artifact_root_candidates(BASE_OUT, dl)}")
            continue

        out_root = _out_root_from_artifacts(artifacts)  # E\
        logs     = _logs_dir(out_root)

        for module_name in MODULES_9:
            if module_name == "INDXRipper":
                _run_indxripper(dl, out_root, KAPE_EXE, logs, TIMEOUT)
            else:
                _run_generic_module(artifacts, out_root, module_name, KAPE_EXE, logs, TIMEOUT)

    return False
