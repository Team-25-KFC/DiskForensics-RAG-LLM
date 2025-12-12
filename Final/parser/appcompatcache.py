#!/usr/bin/env python3
# -*- coding: utf-8 -*-
import subprocess
# // [코드 삽입 시작] 한글 로그 인코딩 통일용
import locale
ENCODING = locale.getpreferredencoding(False)
# // [코드 삽입 끝]
from pathlib import Path
from typing import List

MODULE_NAME = "AppCompatCacheParser"
BIN = Path(r"C:\KAPE\Modules\bin")


def _has() -> bool:
    for p in BIN.rglob("*.exe"):
        if p.name.lower() == "appcompatcacheparser.exe":
            return True
    return False


def _cands(b: Path, d: str) -> list[Path]:
    return [b / f"$NFTS_{d[0]}" / "Artifacts", b / d[0] / "Artifacts"]


def _loc(b: Path, d: str) -> Path | None:
    for p in _cands(b, d):
        if p.exists():
            return p
    return None


def _root(a: Path) -> Path:
    return a.parent


def _stream(cmd: list[str], log: Path, t: int) -> int:
    log.parent.mkdir(parents=True, exist_ok=True)
    # // [코드 삽입 시작] 서브프로세스 출력 + 로그 파일 인코딩을 OS 기본값으로 통일
    with open(log, "w", encoding=ENCODING, errors="replace") as lf:
        lf.write("[CMD] " + " ".join(cmd) + "\n")
        proc = subprocess.Popen(
            cmd,
            stdout=subprocess.PIPE,
            stderr=subprocess.STDOUT,
            text=True,
            encoding=ENCODING,
            errors="replace",
        )
        assert proc.stdout
        try:
            for line in proc.stdout:
                lf.write(line.rstrip() + "\n")
            return proc.wait(timeout=t if t > 0 else None)
        except subprocess.TimeoutExpired:
            proc.kill()
            lf.write("[ERROR] timeout\n")
            return -9
    # // [코드 삽입 끝]


def run(drive_letters: List[str], unmount_callback, cfg: dict) -> bool:
    BASE_OUT: Path = cfg["BASE_OUT"]
    KAPE_EXE: Path = cfg["KAPE_EXE"]
    TO = int(cfg.get("PROC_TIMEOUT_SEC", 1800))

    if not _has():
        print("[SKIP] AppCompatCacheParser: exe not found")
        return False

    for dl in drive_letters:
        art = _loc(BASE_OUT, dl)
        if not art:
            print(f"[SKIP] {dl} AppCompat: Artifacts missing")
            continue

        root = _root(art)
        mdest = root / MODULE_NAME
        log = root / "Logs" / f"{MODULE_NAME}.log"

        cmd = [
            str(KAPE_EXE),
            "--msource",
            str(art),
            "--mdest",
            str(mdest),
            "--module",
            MODULE_NAME,
            "--mef",
            "csv",
            "--vss",
            "false",
        ]

        print(f"[RUN ] {dl} {MODULE_NAME}")
        rc = _stream(cmd, log, TO)

        if rc != 0:
            print(f"[FAIL] {dl} {MODULE_NAME} rc={rc}")
            try:
                if mdest.exists() and not any(mdest.iterdir()):
                    mdest.rmdir()
            except Exception:
                pass
        else:
            print(f"[OK  ] {dl} {MODULE_NAME}")

    return False
