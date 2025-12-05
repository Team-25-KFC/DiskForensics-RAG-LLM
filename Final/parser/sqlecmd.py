# 파일: Final/sqlecmd.py
#!/usr/bin/env python3
# -*- coding: utf-8 -*-
from pathlib import Path
from typing import List
import subprocess

MODULE_NAME = "SQLECmd"

# -----------------------------
# 유틸
# -----------------------------
def _debug_path(p: Path, tag: str):
    try:
        print(f"[DBG ] {tag}: {p} (exists={p.exists()})")
    except Exception:
        pass

def _find_art_root(base_out: Path, dl: str) -> Path | None:
    """Artifacts 루트 탐색 (두 구조 모두 지원)"""
    d = dl.rstrip(":").upper()
    for cand in (
        base_out / d / "Artifacts",
        base_out / f"$NFTS_{d}" / "Artifacts",
    ):
        if cand.exists():
            return cand
    return None

def _ensure_utf8_bom(csv_path: Path):
    """
    CSV를 UTF-8 with BOM으로 보정.
    - 이미 BOM 있으면 스킵
    - UTF-8(무BOM)이면 BOM만 추가
    - 그 외(예: cp949 등)는 복원 후 utf-8-sig로 재저장
    """
    data = csv_path.read_bytes()
    if data.startswith(b"\xef\xbb\xbf"):
        return
    try:
        data.decode("utf-8")
        csv_path.write_bytes(b"\xef\xbb\xbf" + data)
    except UnicodeDecodeError:
        text = data.decode("cp949", errors="replace")
        csv_path.write_bytes(text.encode("utf-8-sig"))

# -----------------------------
# 메인
# -----------------------------
def run(drive_letters: List[str], unmount_callback, cfg: dict) -> bool:
    base_out: Path = cfg["BASE_OUT"]
    to = int(cfg.get("PROC_TIMEOUT_SEC", 1800))
    bin_dir = cfg["KAPE_EXE"].parent / "Modules" / "bin"

    # SQLECmd.exe 탐지 (정확 경로)
    sqle_path = next((p for p in bin_dir.rglob("SQLECmd.exe")), None)
    if not sqle_path:
        print("[SKIP] SQLECmd: exe not found in Modules\\bin")
        return False
    _debug_path(sqle_path, "SQLECmd.exe")

    # Maps 탐지 (둘 중 하나 있으면 사용)
    maps_dir = None
    for cand in ("SQLECmd\\Maps", "SQLMap\\Maps"):
        p = bin_dir / cand
        if p.exists():
            maps_dir = p
            break
    if maps_dir:
        _debug_path(maps_dir, "Maps")

    any_ok = False

    for dl in drive_letters:
        # 1) Artifacts 루트 찾기
        art_root = _find_art_root(base_out, dl)
        if not art_root:
            print(f"[SKIP] {MODULE_NAME}: {dl} Artifacts not found")
            continue

        # 2) 출력 폴더 생성 (BASE_OUT\<드라이브>\SQLECmd\)
        drive_tag = dl.rstrip(":").upper()
        out_dir = base_out / drive_tag / MODULE_NAME
        out_dir.mkdir(parents=True, exist_ok=True)

        _debug_path(art_root, f"src(Artifacts {dl})")
        _debug_path(out_dir,  f"dst(Output {dl})")

        # 3) 전체 경로로 cmd 구성 (shell=False)
        cmd = [str(sqle_path), "-d", str(art_root), "--csv", str(out_dir)]
        if maps_dir:
            cmd += ["--maps", str(maps_dir)]

        try:
            print(f"[RUN ] {MODULE_NAME}: {dl} -d {art_root}")
            cp = subprocess.run(
                cmd,
                capture_output=True,
                text=True,
                timeout=to,
                shell=False
            )
        except subprocess.TimeoutExpired:
            print(f"[TIME] {MODULE_NAME}: {dl} timeout({to}s)")
            continue
        except FileNotFoundError as e:
            print(f"[ERR ] {MODULE_NAME}: {dl} {e}")
            continue
        except Exception as e:
            print(f"[ERR ] {MODULE_NAME}: {dl} {e}")
            continue

        if cp.returncode == 0:
            # 한글 깨짐 방지: 생성된 CSV 전부 BOM 보정
            for csv in out_dir.glob("*.csv"):
                _ensure_utf8_bom(csv)
            print(f"[OK  ] {MODULE_NAME}: {dl}")
            any_ok = True
        else:
            print(f"[FAIL] {MODULE_NAME}: {dl} rc={cp.returncode}")
            if cp.stdout:
                print(cp.stdout.strip())
            if cp.stderr:
                print(cp.stderr.strip())

    return any_ok
