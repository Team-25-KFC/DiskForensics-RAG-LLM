#!/usr/bin/env python3
# -*- coding: utf-8 -*-
r"""
ntfs_modules.py — NTFS 모듈(9개) CSV 실행 워커
(마운트/타깃 복사는 외부 오케스트레이터(main.py + artifacts.py)가 수행)

입력 전제:
  - 타깃 복사본: BASE_OUT\$NFTS_<드라이브>\Artifacts
    (호환: BASE_OUT\<드라이브>\Artifacts)

출력:
  - CSV: BASE_OUT\$NFTS_<드라이브>\<모듈명>\*.csv
  - 로그: BASE_OUT\$NFTS_<드라이브>\Logs\*.log

특이사항:
  - INDXRipper는 모듈 정의상 \\.\%sourceDriveLetter% 접근 → --msource 는 'E:\' 같은 드라이브 루트 사용
  - MFTECmd_*, NTFSLogTracker_*는 복사본(Artifacts) 경로를 --msource 로 사용
"""

import subprocess
from pathlib import Path
from typing import List

# -----------------------------
# 모듈 목록 (총 9)
# -----------------------------
MODULES_9 = [
    #"MFTECmd_$MFT",
    #"MFTECmd_$J",
    #"MFTECmd_$Boot",
    #"MFTECmd_$MFT_FileListing",
    #"MFTECmd_$MFT_ProcessMFTSlack",
    #"MFTECmd_$MFT_DumpResidentFiles",
    "NTFSLogTracker_$J",
    "NTFSLogTracker_$LogFile",
    "INDXRipper",
]

MODULE_BIN_DIR = Path(r"C:\KAPE\Modules\bin")  # 실행 파일 점검용(폴더 내부 포함)

# -----------------------------
# 경로 유틸
# -----------------------------
def _artifact_root_candidates(base_out: Path, dl: str) -> list[Path]:
    # 표준 및 호환 구조 모두 지원
    return [
        base_out / f"$NFTS_{dl[0]}" / "Artifacts",
        base_out / dl[0] / "Artifacts",
    ]

def _artifact_root(base_out: Path, dl: str) -> Path | None:
    for p in _artifact_root_candidates(base_out, dl):
        if p.exists():
            return p
    return None

def _artifact_dir(base_out: Path, dl: str) -> Path:
    d = base_out / f"$NFTS_{dl[0]}"
    d.mkdir(parents=True, exist_ok=True)
    return d

def _logs_dir(base_out: Path, dl: str) -> Path:
    d = base_out / f"$NFTS_{dl[0]}" / "Logs"
    d.mkdir(parents=True, exist_ok=True)
    return d

# -----------------------------
# 실행 파일 점검(Modules\bin 하위 폴더 포함)
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
    # v1.8/1.9 등 버전 폴더명 불문, 실행 파일만 존재하면 True
    return _find_exe_anywhere_by_name("NTFS_Log_Tracker_CMD.exe") is not None

# -----------------------------
# KAPE 호출
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
            rc = proc.wait(timeout=timeout_sec if timeout_sec > 0 else None)
            return rc
        except subprocess.TimeoutExpired:
            proc.kill()
            lf.write("[ERROR] timeout\n")
            return -9

def _run_indxripper(letter: str, artifact_dir: Path, kape_exe: Path, logs_dir: Path, timeout_sec: int):
    """
    INDXRipper 전용: --msource 는 복사본이 아닌 'E:\' 같은 드라이브 루트
    """
    if not _has_indxripper():
        (logs_dir / "INDXRipper.skip.log").write_text("reason=INDXRipper.exe_not_found\n", encoding="utf-8")
        print(f"[SKIP] INDXRipper: 실행 exe 미발견 (Modules\\bin 하위 확인)")
        return

    mdest = artifact_dir / "INDXRipper"
    cmd = [
        str(kape_exe),
        "--msource", f"{letter}\\",
        "--mdest",   str(mdest),
        "--module",  "INDXRipper",
        "--mef",     "csv",
        "--vss",     "false",
    ]
    print(f"[RUN ] INDXRipper (src={letter}\\)")
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

def _run_generic_module(msource: Path, artifact_dir: Path, module_name: str,
                        kape_exe: Path, logs_dir: Path, timeout_sec: int):
    """
    MFTECmd_*, NTFSLogTracker_* 공용 실행기 (CSV)
    """
    # 사전 실행 파일 점검 (빈 폴더 방지용)
    base = module_name.split("_", 1)[0].lower()
    if base.startswith("mftecmd"):
        if not _has_mftecmd():
            (logs_dir / f"{module_name}.skip.log").write_text("reason=MFTECmd.exe_not_found\n", encoding="utf-8")
            print(f"[SKIP] {module_name}: MFTECmd.exe 없음")
            return
    elif base.startswith("ntfslogtracker"):
        if not _has_ntfs_log_tracker_any_ver():
            (logs_dir / f"{module_name}.skip.log").write_text("reason=NTFS_Log_Tracker_CMD.exe_not_found\n", encoding="utf-8")
            print(f"[SKIP] {module_name}: NTFS_Log_Tracker_CMD.exe 없음")
            return
        # 주의: .mkape가 v1.8 경로를 하드코딩했을 수 있음 → 경고 로그
        (logs_dir / f"{module_name}.warn.log").write_text(
            "note=.mkape may reference v1.8; ensure it matches installed version (e.g., v1.9)\n",
            encoding="utf-8"
        )

    mdest = artifact_dir / module_name
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
# 엔트리포인트 (오케스트레이터 호출)
# -----------------------------
def run(drive_letters: List[str], unmount_callback, cfg: dict) -> bool:
    """
    main.py에서 호출:
      - drive_letters: ['E:', 'I:', ...]
      - unmount_callback: 사용 안 함(여기서는 언마운트하지 않음)
      - cfg: {"BASE_OUT": Path, "KAPE_EXE": Path, "PROC_TIMEOUT_SEC": int}
    반환: False (언마운트는 메인에서 수행)
    """
    BASE_OUT: Path = cfg["BASE_OUT"]
    KAPE_EXE: Path  = cfg["KAPE_EXE"]
    TIMEOUT:  int   = int(cfg.get("PROC_TIMEOUT_SEC", 1800))

    for dl in drive_letters:
        artifacts = _artifact_root(BASE_OUT, dl)
        if not artifacts:
            print(f"[SKIP] {dl} ntfs-modules: Artifacts 부재 → {_artifact_root_candidates(BASE_OUT, dl)}")
            continue

        art_dir = _artifact_dir(BASE_OUT, dl)
        logs    = _logs_dir(BASE_OUT, dl)

        for module_name in MODULES_9:
            if module_name == "INDXRipper":
                _run_indxripper(dl, art_dir, KAPE_EXE, logs, TIMEOUT)
            else:
                _run_generic_module(artifacts, art_dir, module_name, KAPE_EXE, logs, TIMEOUT)

    return False  # 언마운트는 메인에서
