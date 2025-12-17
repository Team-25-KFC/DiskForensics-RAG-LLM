#!/usr/bin/env python3
# -*- coding: utf-8 -*-
import subprocess
from pathlib import Path
from typing import List

# -----------------------------
# 모듈 목록 (총 9)
# -----------------------------
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

# EZTools 모듈 실행파일이 위치한 기본 폴더(하위 폴더 포함 검색)
MODULE_BIN_DIR = Path(r"C:\KAPE\Modules\bin")

# =============================
# 경로 유틸
# =============================
def _artifact_root_candidates(base_out: Path, dl: str) -> list[Path]:
    L = dl[0].upper()
    return [
        base_out / L / "Artifacts",
        base_out / f"$NFTS_{L}" / "Artifacts",
    ]

def _artifact_root(base_out: Path, dl: str) -> Path | None:
    """
    '존재'가 아니라 '비어있지 않은' 경로를 우선 선택.
    둘 다 비어있으면 존재하는 쪽을 그래도 반환(폴백).
    """
    candidates = _artifact_root_candidates(base_out, dl)
    empty_fallback = None

    for p in candidates:
        if p.exists():
            try:
                if any(p.iterdir()):  # 내용이 하나라도 있으면 채택
                    return p
                else:
                    empty_fallback = p  # 존재하지만 비어있음 → 폴백 저장
            except Exception:
                continue

    return empty_fallback

def _out_root_from_artifacts(artifacts: Path) -> Path:
    return artifacts.parent

def _logs_dir(out_root: Path) -> Path:
    d = out_root / "Logs"
    d.mkdir(parents=True, exist_ok=True)
    return d

# 드라이브 루트 정규화(E:, E:\ 혼선 방지)
def _drive_root(letter: str) -> str:
    l = letter.strip()
    if len(l) == 2 and l[1] == ":":
        return f"{l}\\"
    if l.endswith(":\\"):
        return l
    if l.endswith(":"):
        return l + "\\"
    return l

# =============================
# 실행 파일 점검
# =============================
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
    # v1.8/1.9 등 폴더명 불문, 실행 파일만 있으면 True
    return _find_exe_anywhere_by_name("NTFS_Log_Tracker_CMD.exe") is not None

# =============================
# KAPE 실행기
# =============================
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

def _cleanup_empty_dir(p: Path):
    try:
        if p.exists() and not any(p.iterdir()):
            p.rmdir()
    except Exception:
        pass

def _run_indxripper(letter: str, out_root: Path, kape_exe: Path, logs_dir: Path, timeout_sec: int):
    """
    INDXRipper 전용: --msource 는 복사본이 아닌 'E:\' 같은 드라이브 루트.
    마운트가 내려가 있으면 즉시 스킵 로그 남김.
    """
    if not _has_indxripper():
        (logs_dir / "INDXRipper.skip.log").write_text("reason=INDXRipper.exe_not_found\n", encoding="utf-8")
        print(f"[SKIP] INDXRipper: exe not found")
        return False

    src = _drive_root(letter)
    if not Path(src).exists():
        (logs_dir / "INDXRipper.skip.log").write_text(f"reason=drive_root_missing src={src}\n", encoding="utf-8")
        print(f"[SKIP] INDXRipper: drive not mounted ({src})")
        return False

    mdest = out_root / "INDXRipper"
    cmd = [
        str(kape_exe),
        "--msource", src,           # 드라이브 루트
        "--mdest",   str(mdest),
        "--module",  "INDXRipper",
        "--mef",     "csv",
        "--vss",     "false",
    ]
    print(f"[RUN ] INDXRipper ({src})")
    rc = _stream_kape(cmd, logs_dir / "INDXRipper.log", timeout_sec)
    if rc != 0:
        print(f"[FAIL] INDXRipper rc={rc}")
        _cleanup_empty_dir(mdest)
        return False
    else:
        print(f"[OK  ] INDXRipper")
        return True

def _run_generic_module(msource: Path, out_root: Path, module_name: str,
                        kape_exe: Path, logs_dir: Path, timeout_sec: int):
    """
    MFTECmd_*, NTFSLogTracker_* 공용 실행기 (CSV)
    - 존재 exe 확인 → 없으면 skip.log 기록
    """
    base = module_name.split("_", 1)[0].lower()
    if base.startswith("mftecmd"):
        if not _has_mftecmd():
            (logs_dir / f"{module_name}.skip.log").write_text("reason=MFTECmd.exe_not_found\n", encoding="utf-8")
            print(f"[SKIP] {module_name}: MFTECmd.exe not found")
            return False
    elif base.startswith("ntfslogtracker"):
        if not _has_ntfs_log_tracker_any_ver():
            (logs_dir / f"{module_name}.skip.log").write_text("reason=NTFS_Log_Tracker_CMD.exe_not_found\n", encoding="utf-8")
            print(f"[SKIP] {module_name}: NTFS_Log_Tracker_CMD.exe not found")
            return False
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
        _cleanup_empty_dir(mdest)
        return False
    else:
        print(f"[OK  ] {module_name}")
        return True

# =============================
# 엔트리포인트
# =============================
def run(drive_letters: List[str], unmount_callback, cfg: dict) -> bool:
    """
    오케스트레이터가 호출하는 표준 엔트리포인트.
    - drive_letters: ['E:', 'J:', 'I:']
    - cfg: {"BASE_OUT": Path, "KAPE_EXE": Path, "PROC_TIMEOUT_SEC": int}
    반환: 하나라도 성공하면 True, 아니면 False
    """
    BASE_OUT: Path = cfg["BASE_OUT"]
    KAPE_EXE: Path = cfg["KAPE_EXE"]
    TO: int = int(cfg.get("PROC_TIMEOUT_SEC", 1800))

    any_ok = False

    for dl in drive_letters:
        # Artifacts 루트(우선: <BASE_OUT>\<E>\Artifacts, 보조: <BASE_OUT>\$NFTS_E\Artifacts)
        art = _artifact_root(BASE_OUT, dl)
        out_root = _out_root_from_artifacts(art) if art else (BASE_OUT / dl[0].upper())
        logs_dir = _logs_dir(out_root)

        # 1) INDXRipper: 항상 드라이브 루트(\\.\%sourceDriveLetter%) 접근 → Artifacts 없어도 시도
        if "INDXRipper" in MODULES_9:
            ok = _run_indxripper(dl, out_root, KAPE_EXE, logs_dir, TO)
            any_ok = any_ok or ok

        # 2) 그 외 MFTECmd_*, NTFSLogTracker_* 계열: Artifacts가 있어야 의미 있음
        if art is None:
            print(f"[SKIP] {dl} NTFS generic: Artifacts not found")
        else:
            for m in MODULES_9:
                if m == "INDXRipper":
                    continue
                ok = _run_generic_module(art, out_root, m, KAPE_EXE, logs_dir, TO)
                any_ok = any_ok or ok

    return any_ok
