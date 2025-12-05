# 파일: Final/srumecmd.py
#!/usr/bin/env python3
# -*- coding: utf-8 -*-
from pathlib import Path
from typing import List
import subprocess

MODULE_NAME = "SrumECmd"  # 표준 모듈명과 통일

# -----------------------------
# 유틸
# -----------------------------
def _debug(p: Path | str, tag: str):
    try:
        q = Path(p)
        print(f"[DBG ] {tag}: {q} (exists={q.exists()})")
    except Exception:
        print(f"[DBG ] {tag}: {p}")

def _find_art_root(base_out: Path, dl: str) -> Path | None:
    """Artifacts 루트를 BASE_OUT\\<드라이브> 우선, $NFTS_* 호환."""
    d = dl.rstrip(":").upper()
    for cand in (base_out / d / "Artifacts", base_out / f"$NFTS_{d}" / "Artifacts"):
        if cand.exists():
            return cand
    return None

def _find_first(root: Path, name: str) -> Path | None:
    """root 이하에서 파일명 일치 첫 경로 반환 (대소문자 무시)"""
    lower = name.lower()
    for p in root.rglob("*"):
        if p.name.lower() == lower:
            return p
    return None

# -----------------------------
# 메인
# -----------------------------
def run(drive_letters: List[str], unmount_callback, cfg: dict) -> bool:
    """
    KAPE 모듈 대신 직접 SrumECmd.exe 실행:
      -f <SRUDB.dat>  -r <SOFTWARE>  --csv <...\\SRUMDatabase>
    """
    base_out: Path = cfg["BASE_OUT"]
    to = int(cfg.get("PROC_TIMEOUT_SEC", 1800))
    bin_dir = cfg["KAPE_EXE"].parent / "Modules" / "bin"

    # SrumECmd.exe 탐지
    srum_exe = next((p for p in bin_dir.rglob("SrumECmd.exe")), None)
    if not srum_exe:
        print("[SKIP] SrumECmd: exe not found in Modules\\bin")
        return False
    _debug(srum_exe, "SrumECmd.exe")

    any_ok = False

    for dl in drive_letters:
        art_root = _find_art_root(base_out, dl)
        if not art_root:
            print(f"[SKIP] {MODULE_NAME}: {dl} Artifacts not found")
            continue

        # SRUDB.dat / SOFTWARE 재귀 탐색
        sru_db   = _find_first(art_root, "SRUDB.dat")
        software = _find_first(art_root, "SOFTWARE")

        _debug(art_root,  f"src(Artifacts {dl})")
        _debug(sru_db or "N/A",     f"SRUDB.dat {dl}")
        _debug(software or "N/A",   f"SOFTWARE {dl}")

        if not sru_db:
            print(f"[SKIP] {MODULE_NAME}: {dl} SRUDB.dat not found under Artifacts")
            continue
        if not software:
            print(f"[SKIP] {MODULE_NAME}: {dl} SOFTWARE hive not found under Artifacts")
            continue

        # 출력 위치
        dtag = dl.rstrip(":").upper()
        out_dir = base_out / dtag / "SrumECmd" / "SRUMDatabase"
        out_dir.mkdir(parents=True, exist_ok=True)
        _debug(out_dir, f"dst(Output {dl})")

        # 직접 실행
        cmd = [
            str(srum_exe),
            "-f",   str(sru_db),
            "-r",   str(software),
            "--csv", str(out_dir),
        ]

        try:
            print(f"[RUN ] {MODULE_NAME}: {dl} → -f {sru_db.name} -r SOFTWARE")
            cp = subprocess.run(cmd, capture_output=True, text=True, timeout=to, shell=False)
        except subprocess.TimeoutExpired:
            print(f"[TIME] {MODULE_NAME}: {dl} timeout({to}s)")
            continue
        except Exception as e:
            print(f"[ERR ] {MODULE_NAME}: {dl} {type(e).__name__}: {e}")
            continue

        if cp.returncode == 0:
            print(f"[OK  ] {MODULE_NAME}: {dl}")
            any_ok = True
        else:
            print(f"[FAIL] {MODULE_NAME}: {dl} rc={cp.returncode}")
            if cp.stdout: print(cp.stdout.strip())
            if cp.stderr: print(cp.stderr.strip())

    return any_ok
