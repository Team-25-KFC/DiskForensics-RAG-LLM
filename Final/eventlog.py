#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
eventlog.py — EvtxECmd(KAPE 모듈) 래퍼 (Win10/11)

전제:
  - 마운트/타깃 복사는 외부 오케스트레이터(main.py + artifacts.py)에서 수행
  - 아티팩트 복사본은 다음 중 하나로 존재:
      <BASE_OUT>\<E>\Artifacts\<E>      (우선)
      <BASE_OUT>\<E>\Artifacts          (폴백)
      <BASE_OUT>\$NFTS_E\Artifacts     (호환)

출력:
  - CSV: <BASE_OUT>\<E>\EvtxECmd\*.csv
  - 로그: <BASE_OUT>\<E>\Logs\eventlogs_E_module_runlog.txt
"""

import subprocess
from pathlib import Path
from typing import List, Optional

# ───────────────────────────── 공용 경로 유틸 ─────────────────────────────

def _bin_dir(kape_exe: Path) -> Path:
    """KAPE Modules bin 디렉터리"""
    return kape_exe.parent / "Modules" / "bin"

def _has_evtxecmd(kape_exe: Path) -> bool:
    """Modules\\bin 하위에서 EvtxECmd.exe 존재 여부"""
    b = _bin_dir(kape_exe)
    if not b.exists():
        return False
    for p in b.rglob("*.exe"):
        if p.name.lower() == "evtxecmd.exe":
            return True
    return False

def _artifacts_root(base_out: Path, drive_letter: str) -> Path:
    """드라이브별 아티팩트 루트(드라이브문자 우선, $NFTS_* 호환 지원)"""
    L = drive_letter[0]
    p1 = base_out / L / "Artifacts"
    if p1.exists():
        return p1
    return base_out / f"$NFTS_{L}" / "Artifacts"

def _resolve_msource(artifacts_root: Path, drive_letter: str) -> Path:
    """모듈 msource: <Artifacts>\<E>가 있으면 그쪽, 없으면 <Artifacts> 루트"""
    L = drive_letter[0]
    sub = artifacts_root / L
    return sub if sub.exists() else artifacts_root

def _ensure_dirs(p: Path) -> Path:
    p.mkdir(parents=True, exist_ok=True)
    return p

def _has_evtx(msource: Path) -> bool:
    """msource 내 EVTX 존재 여부(Logs 폴더 또는 *.evtx 존재)"""
    logs = msource / "Windows" / "System32" / "winevt" / "Logs"
    if logs.is_dir():
        return True
    for _ in msource.rglob("*.evtx"):
        return True
    return False

def _marker(base_out: Path, dl: str) -> Path:
    """드라이브별 완료 마커 파일 경로"""
    return base_out / dl[0] / ".modules_eventlogs_csv_done"

# ───────────────────────────── KAPE 실행기 ─────────────────────────────

def _run_evtxecmd(kape_exe: Path, msource: Path, mdest: Path,
                  timeout_sec: int, log_path: Path) -> int:
    """EvtxECmd 모듈 실행(타임아웃/로그 처리, 반환코드 리턴)"""
    cmd = [
        str(kape_exe),
        "--module", "EvtxECmd",
        "--msource", str(msource),
        "--mdest",   str(mdest),
        "--mef",     "csv",
        "--vss",     "false",
    ]
    mdest.mkdir(parents=True, exist_ok=True)
    log_path.parent.mkdir(parents=True, exist_ok=True)
    with open(log_path, "w", encoding="utf-8") as lf:
        lf.write("[CMD] " + " ".join(cmd) + "\n")
        proc = subprocess.Popen(cmd, stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True)
        try:
            assert proc.stdout
            for line in proc.stdout:
                line = line.rstrip()
                print(line)
                lf.write(line + "\n")
            return proc.wait(timeout=timeout_sec if timeout_sec and timeout_sec > 0 else None)
        except subprocess.TimeoutExpired:
            proc.kill()
            lf.write("[ERROR] timeout\n")
            return -9

# ───────────────────────────── 엔트리포인트 ─────────────────────────────

def run(drive_letters: List[str], unmount_callback, cfg: dict) -> bool:
    """
    cfg 예시:
      {
        "BASE_OUT": Path(r"D:\Kape Output"),
        "KAPE_EXE": Path(r"D:\KAPE\kape.exe"),
        "PROC_TIMEOUT_SEC": 1800
      }
    """
    BASE_OUT: Path = cfg["BASE_OUT"]
    KAPE_EXE:  Path = cfg["KAPE_EXE"]
    TIMEOUT:   int  = int(cfg.get("PROC_TIMEOUT_SEC", 1800))

    # EvtxECmd 존재하지 않으면 전체 스킵
    if not _has_evtxecmd(KAPE_EXE):
        print(f"[SKIP] eventlogs: EvtxECmd.exe 미존재 → {_bin_dir(KAPE_EXE)}")
        return False

    try:
        for dl in drive_letters:
            mark = _marker(BASE_OUT, dl)
            if mark.exists():
                print(f"[SKIP] {dl} eventlogs: 이미 CSV 모듈 처리 완료 ({mark})")
                continue

            artifacts_root = _artifacts_root(BASE_OUT, dl)
            if not artifacts_root.exists():
                print(f"[SKIP] {dl} eventlogs: Artifacts 부재 → {artifacts_root}")
                continue

            msource = _resolve_msource(artifacts_root, dl)
            if not _has_evtx(msource):
                print(f"[SKIP] {dl} eventlogs: EVTX 없음 → {msource}")
                continue

            mdest = _ensure_dirs(BASE_OUT / dl[0] / "EvtxECmd")
            logs  = _ensure_dirs(BASE_OUT / dl[0] / "Logs")
            log_path = logs / f"eventlogs_{dl[0]}_module_runlog.txt"

            print(f"[RUN ] {dl} eventlogs(csv): msource={msource} → mdest={mdest}")
            rc = _run_evtxecmd(KAPE_EXE, msource, mdest, TIMEOUT, log_path)
            if rc != 0:
                print(f"[FAIL] {dl} eventlogs(csv): rc={rc} → {mdest}")
                continue

            try:
                mark.write_text("done", encoding="utf-8")
            except Exception:
                pass
            print(f"[OK  ] {dl} eventlogs(csv): 완료 → {mdest}")

        return False  # 언마운트는 메인에서 처리
    except Exception as e:
        print(f"[FATAL] eventlogs 모듈 실행 실패: {e}")
        return False
