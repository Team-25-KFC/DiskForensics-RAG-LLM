#!/usr/bin/env python3
# -*- coding: utf-8 -*-
import subprocess
from pathlib import Path
from typing import List

MODULE_NAME = "JLECmd"
MODULE_BIN_DIR = Path(r"C:\KAPE\Modules\bin")


def _find_exe(exe: str) -> bool:
    for p in MODULE_BIN_DIR.rglob("*.exe"):
        if p.name.lower() == exe.lower():
            return True
    return False


def _cands(b: Path, d: str) -> list[Path]:
    return [b / f"$NFTS_{d[0]}" / "Artifacts", b / d[0] / "Artifacts"]


def _loc(b: Path, d: str) -> Path | None:
    for p in _cands(b, d):
        if p.exists():
            return p
    return None


def _out(art: Path) -> Path:
    return art.parent


def _stream(cmd: list[str], log: Path, t: int) -> int:
    log.parent.mkdir(parents=True, exist_ok=True)

    # 로그 파일은 UTF-8로 작성 (stdout 디코딩은 별도 처리)
    with open(log, "w", encoding="utf-8") as lf:
        lf.write("[CMD] " + " ".join(cmd) + "\n")

        # // [코드 삽입 시작]
        # stdout을 bytes로 받고, 우리가 직접 안전하게 디코딩(UTF-8 실패 시 CP949/mbcs 등 fallback)
        proc = subprocess.Popen(
            cmd,
            stdout=subprocess.PIPE,
            stderr=subprocess.STDOUT,
            text=False,  # 중요: 자동 디코딩(환경 의존) 방지
        )
        assert proc.stdout

        def _safe_decode(b: bytes) -> str:
            for enc in ("utf-8", "utf-8-sig", "cp949", "mbcs"):
                try:
                    return b.decode(enc)
                except UnicodeDecodeError:
                    pass
            return b.decode("utf-8", errors="replace")
        # // [코드 삽입 끝]

        try:
            # // [코드 삽입 시작]
            for raw in proc.stdout:
                line = _safe_decode(raw).rstrip("\r\n")
                lf.write(line + "\n")
            # // [코드 삽입 끝]

            return proc.wait(timeout=t if t > 0 else None)

        except subprocess.TimeoutExpired:
            proc.kill()
            lf.write("[ERROR] timeout\n")
            return -9


def run(drive_letters: List[str], unmount_callback, cfg: dict) -> bool:
    BASE_OUT: Path = cfg["BASE_OUT"]
    KAPE_EXE: Path = cfg["KAPE_EXE"]
    TO = int(cfg.get("PROC_TIMEOUT_SEC", 1800))

    if not _find_exe("JLECmd.exe"):
        print("[SKIP] JLECmd: exe not found")
        return False

    for dl in drive_letters:
        art = _loc(BASE_OUT, dl)
        if not art:
            print(f"[SKIP] {dl} JLECmd: Artifacts missing")
            continue

        root = _out(art)
        mdest = root / MODULE_NAME
        log = root / "Logs" / f"{MODULE_NAME}.log"

        cmd = [
            str(KAPE_EXE),
            "--msource", str(art),
            "--mdest", str(mdest),
            "--module", MODULE_NAME,
            "--mef", "csv",
            "--vss", "false",
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
