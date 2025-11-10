#!/usr/bin/env python3
# -*- coding: utf-8 -*-
from pathlib import Path
from typing import List
import subprocess

MODULE_NAME = "SQLECmd"

def run(drive_letters: List[str], unmount_callback, cfg: dict) -> bool:
    base_out: Path = cfg["BASE_OUT"]
    to = int(cfg.get("PROC_TIMEOUT_SEC", 1800))
    bin_dir = cfg["KAPE_EXE"].parent / "Modules" / "bin"

    # SQLECmd.exe & Maps
    sqle = next((p for p in bin_dir.rglob("SQLECmd.exe")), None)
    if not sqle: 
        print("[SKIP] SQLECmd: exe not found"); 
        return False
    maps = bin_dir / "SQLMap" / "Maps"
    if not maps.exists(): maps = None

    def art_root(dl: str) -> Path | None:
        d = dl.rstrip(":").upper()
        for p in (base_out / f"$NFTS_{d}" / "Artifacts", base_out / d / "Artifacts"):
            if p.exists(): return p
        return None

    def profiles(art: Path):
        pats = [
            r"E\Users\*\AppData\Local\Google\Chrome\User Data\*",
            r"E\Users\*\AppData\Local\Microsoft\Edge\User Data\*",
            r"Users\*\AppData\Local\Google\Chrome\User Data\*",
            r"Users\*\AppData\Local\Microsoft\Edge\User Data\*",
        ]
        seen = set()
        for g in pats:
            for p in art.glob(g):
                if p.is_dir() and p not in seen:
                    seen.add(p); yield p

    def has_db(p: Path) -> bool:
        return (p/"History").exists() or (p/"Login Data").exists() or (p/"Network"/"Cookies").exists()

    any_exec = False
    for dl in drive_letters:
        art = art_root(dl)
        if not art: 
            print(f"[SKIP] {dl} SQLECmd: Artifacts missing"); 
            continue
        out_root = art.parent / MODULE_NAME
        log = art.parent / "Logs" / f"{MODULE_NAME}.log"
        out_root.mkdir(parents=True, exist_ok=True); log.parent.mkdir(parents=True, exist_ok=True)

        targets = [p for p in profiles(art) if has_db(p)]
        if not targets:
            print(f"[SKIP] {dl} SQLECmd: No Chromium profiles with core DBs"); 
            continue
        print(f"[RUN ] {dl} SQLECmd: {len(targets)} profiles")

        with open(log, "a", encoding="utf-8") as lf:
            for prof in targets:
                dest = out_root / prof.name; dest.mkdir(parents=True, exist_ok=True)
                cmd = [str(sqle), "-d", str(prof), "--csv", str(dest), "-q"]
                if maps: cmd += ["--maps", str(maps)]
                lf.write("[CMD] " + " ".join(cmd) + "\n")
                proc = subprocess.run(cmd, capture_output=True, text=True, timeout=to)
                lf.write((proc.stdout or "") + (proc.stderr or ""))
                if proc.returncode == 0:
                    print(f"[OK  ] {dl} {prof.name}"); any_exec = True
                else:
                    print(f"[FAIL] {dl} {prof.name} rc={proc.returncode}")
                    try:
                        if not any(dest.iterdir()): dest.rmdir()
                    except Exception: pass

        # 0바이트 CSV 정리
        for f in out_root.rglob("*.csv"):
            try:
                if f.stat().st_size == 0: f.unlink()
            except Exception: pass

    return any_exec
