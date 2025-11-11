#!/usr/bin/env python3
# -*- coding: utf-8 -*-
r"""
srum.py — SrumECmd를 KAPE 모듈(.mkape)로 실행 (메인 코드 수정 불필요)

전략:
  - cfg['KAPE_EXE']가 오염됐어도 무시 가능.
  - D:\KAPE\Modules\bin\SrumECmd.exe 같은 '실물' 바이너리를 rglob로 찾아서
    → ...\Modules\bin\  → \Modules → \KAPE (루트) → kape.exe 를 역산해 사용.
  - 리스트 인자 + shell=False 로만 실행(따옴표 불필요).

입력:
  - drive_letters: ["E:", "J:", ...]
  - cfg: {
      "BASE_OUT": Path|str,        # 예: D:\Kape Output
      "KAPE_EXE": Path|str|None,   # (무시 가능; 없으면 자동 탐색)
      "PROC_TIMEOUT_SEC": int,     # (옵션) 기본 1800
    }

출력:
  - <BASE_OUT>\<드라이브>\SrumECmd\*.csv
"""

from __future__ import annotations
from pathlib import Path
from typing import List, Iterable
import subprocess

MODULE_NAME = "SrumECmd"
MKAPE_NAME  = "SrumECmd"

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
    SrumECmd.exe의 실제 위치를 시스템 전체에서 탐색(빠른 후보 → D:, C: 순).
    발견 시 KAPE 루트(…\KAPE\kape.exe) 경로를 역산해 반환.
    """
    candidates = [Path("D:/KAPE"), Path("C:/KAPE")]
    for root in candidates:
        exe = root / "Modules" / "bin" / "SrumECmd.exe"
        if exe.exists():
            kape_exe = root / "kape.exe"
            return kape_exe if kape_exe.exists() else None

    # 최후: 드라이브 루트 몇 개만 얕게 스캔
    for drive in ["D:/", "C:/", "E:/", "F:/"]:
        try:
            for exe in Path(drive).glob("**/Modules/bin/SrumECmd.exe"):
                kape_root = exe.parent.parent.parent  # bin -> Modules -> KAPE
                kape_exe = kape_root / "kape.exe"
                if kape_exe.exists():
                    return kape_exe
        except Exception:
            pass
    return None

def run(drive_letters: List[str], unmount_callback, cfg: dict) -> bool:
    base_out = _as_path(cfg.get("BASE_OUT", "D:/Kape Output"))
    to = int(cfg.get("PROC_TIMEOUT_SEC", 1800))

    # 1) kape.exe 경로 확보 (cfg 무시 가능)
    kape_exe = _find_kape_from_module_exe()
    if not kape_exe:
        # cfg 제공값이 있으면 마지막 시도
        maybe = cfg.get("KAPE_EXE")
        if maybe:
            kape_exe = _as_path(maybe)
    if not kape_exe or not kape_exe.exists():
        print("[ERR ] kape.exe 를 찾을 수 없습니다. (Modules/bin/SrumECmd.exe 기반 역산 실패)")
        return False

    # 2) mkape 존재 확인
    modules_dir = kape_exe.parent / "Modules"
    if not any((modules_dir / f"{MKAPE_NAME}.mkape").exists() for _ in [0]) \
       and not any(modules_dir.rglob(f"{MKAPE_NAME}.mkape")):
        print(f"[ERR ] Modules에 {MKAPE_NAME}.mkape 없음 → KAPE 모듈 실행 불가")
        return False

    def _art_root(dl: str) -> Path | None:
        d = dl.rstrip(":").upper()
        for p in (base_out / f"$NFTS_{d}" / "Artifacts",
                  base_out / d / "Artifacts"):
            if p.exists():
                return p
        return None

    ok_any = False
    for dl in drive_letters:
        src = _art_root(dl)
        if not src:
            print(f"[SKIP] {dl}: Artifacts 미존재")
            continue

        if not any(src.rglob("SRUDB.dat")):
            print(f"[SKIP] {dl}: SRUDB.dat 없음")
            continue

        out_dir = _ensure_dir(base_out / dl.rstrip(":").upper() / "SrumECmd")

        cmd = [
            str(kape_exe),
            "--msource", str(src),
            "--mdest",   str(out_dir),
            "--module",  MKAPE_NAME,
            "--mef",     "csv",
            "--vss",     "false",
        ]
        print(f"[DBG ] {dl}: KAPE module cmd(list)={cmd}")
        try:
            _run(cmd, to)
            print(f"[OK  ] {dl}: SrumECmd via KAPE")
            ok_any = True
        except subprocess.CalledProcessError as e:
            print(f"[ERR ] {dl}: SrumECmd(KAPE) 실패 (rc={e.returncode})")
        except subprocess.TimeoutExpired:
            print(f"[ERR ] {dl}: SrumECmd(KAPE) 타임아웃({to}s)")

    return ok_any
