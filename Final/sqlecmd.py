#!/usr/bin/env python3
# -*- coding: utf-8 -*-
r"""
sqlecmd.py — SQLECmd를 KAPE 모듈(.mkape)로 실행 (메인 코드 수정 불필요)

전략:
  - cfg의 KAPE_EXE가 오염돼도 무시 가능.
  - 실제 SQLECmd.exe 위치 기반으로 KAPE 루트를 역산해 kape.exe 사용.
  - 크로뮴 프로필(History/Cookies/Login Data/Web Data/Favicons 중 ≥2개) 자동 감지.
  - 리스트 인자 + shell=False만 사용.

출력:
  - <BASE_OUT>\<드라이브>\SQLECmd\profile_XX\*.csv
"""

from __future__ import annotations
from pathlib import Path
from typing import List, Dict, Set, Iterable
import subprocess

MODULE_NAME = "SQLECmd"
MKAPE_NAME  = "SQLECmd"

def _as_path(x) -> Path:
    return x if isinstance(x, Path) else Path(str(x))

def _ensure_dir(p: Path) -> Path:
    p.mkdir(parents=True, exist_ok=True)
    return p

def _run(cmd: list[str], timeout_sec: int):
    print(f"[DBG ] exec(list)={cmd}")
    return subprocess.run(cmd, check=True, timeout=timeout_sec, shell=False)

def _find_kape_from_module_exe() -> Path | None:
    """
    SQLECmd.exe의 실제 위치를 탐색 → KAPE 루트 역산 → kape.exe 반환
    """
    candidates = [Path("D:/KAPE"), Path("C:/KAPE")]
    for root in candidates:
        exe = root / "Modules" / "bin" / "SQLECmd" / "SQLECmd.exe"
        if exe.exists():
            kape_exe = root / "kape.exe"
            return kape_exe if kape_exe.exists() else None

    for drive in ["D:/", "C:/", "E:/", "F:/"]:
        try:
            for exe in Path(drive).glob("**/Modules/bin/SQLECmd/SQLECmd.exe"):
                kape_root = exe.parent.parent.parent  # SQLECmd -> bin -> Modules -> KAPE
                kape_exe = kape_root / "kape.exe"
                if kape_exe.exists():
                    return kape_exe
        except Exception:
            pass
    return None

def run(drive_letters: List[str], unmount_callback, cfg: dict) -> bool:
    base_out = _as_path(cfg.get("BASE_OUT", "D:/Kape Output"))
    to = int(cfg.get("PROC_TIMEOUT_SEC", 1800))

    # 1) kape.exe 경로 확보
    kape_exe = _find_kape_from_module_exe()
    if not kape_exe:
        maybe = cfg.get("KAPE_EXE")
        if maybe:
            kape_exe = _as_path(maybe)
    if not kape_exe or not kape_exe.exists():
        print("[ERR ] kape.exe 를 찾을 수 없습니다. (Modules/bin/SQLECmd/SQLECmd.exe 기반 역산 실패)")
        return False

    # 2) mkape 존재 확인
    modules_dir = kape_exe.parent / "Modules"
    if not any((modules_dir / f"{MKAPE_NAME}.mkape").exists() for _ in [0]) \
       and not any(modules_dir.rglob(f"{MKAPE_NAME}.mkape")):
        print(f"[ERR ] Modules에 {MKAPE_NAME}.mkape 없음 → KAPE 모듈 실행 불가")
        return False

    CORE_DB = {"History", "Cookies", "Login Data", "Web Data", "Favicons"}

    def _art_root(dl: str) -> Path | None:
        d = dl.rstrip(":").upper()
        for p in (base_out / f"$NFTS_{d}" / "Artifacts",
                  base_out / d / "Artifacts"):
            if p.exists():
                return p
        return None

    def _find_profiles(root: Path) -> Set[Path]:
        hits: Dict[Path, Set[str]] = {}
        for name in CORE_DB:
            for f in root.rglob(name):
                prof = f.parent
                hits.setdefault(prof, set()).add(name)
        return {p for p, s in hits.items() if len(s) >= 2}  # 필요시 >=1로 완화

    ok_any = False
    for dl in drive_letters:
        src_root = _art_root(dl)
        if not src_root:
            print(f"[SKIP] {dl}: Artifacts 미존재")
            continue

        profs = _find_profiles(src_root)
        if not profs:
            print(f"[SKIP] {dl}: No Chromium profiles with core DBs (Artifacts 기준)")
            continue

        out_root = _ensure_dir(base_out / dl.rstrip(":").upper() / "SQLECmd")

        for idx, pdir in enumerate(sorted(profs)):
            out_dir = _ensure_dir(out_root / f"profile_{idx+1:02d}")

            cmd = [
                str(kape_exe),
                "--msource", str(pdir),
                "--mdest",   str(out_dir),
                "--module",  MKAPE_NAME,
                "--mef",     "csv",
                "--vss",     "false",
            ]
            print(f"[DBG ] {dl}: KAPE module cmd(list)={cmd} (profile={pdir})")
            try:
                _run(cmd, to)
                ok_any = True
            except subprocess.CalledProcessError as e:
                print(f"[ERR ] {dl}: SQLECmd(KAPE) 실패 (rc={e.returncode}) profile={pdir}")
            except subprocess.TimeoutExpired:
                print(f"[ERR ] {dl}: SQLECmd(KAPE) 타임아웃({to}s) profile={pdir}")

    return ok_any
