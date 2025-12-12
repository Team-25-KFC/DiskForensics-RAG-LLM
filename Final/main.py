#!/usr/bin/env python3
# -*- coding: utf-8 -*-
import importlib
import subprocess
import time
import re
import os
import inspect
from pathlib import Path
from typing import List, Optional
from concurrent.futures import ThreadPoolExecutor, as_completed

# ── 기본값(환경변수로 덮어쓰기 가능) ─────────────────────────
AIM_EXE  = os.getenv("AIM_EXE",  r"C:\Arsenal-Image-Mounter-v3.12.331\aim_cli.exe")
# 환경변수에 E01_PATH가 지정된 경우에만 힌트로 사용, 기본은 "완전 미지정"
E01_PATH = os.getenv("E01_PATH", "").strip()
KAPE_EXE = os.getenv("KAPE_EXE", r"C:\KAPE\kape.exe")

# BASE_OUT_ENV: 실제 BASE_OUT은 main() 안에서 E01 위치 기준으로 결정
BASE_OUT_ENV = os.getenv("BASE_OUT")

MOUNT_STABILIZE_SEC = int(os.getenv("MOUNT_STABILIZE_SEC", "15"))
PS_TIMEOUT_SEC      = int(os.getenv("PS_TIMEOUT_SEC", "90"))
PROC_TIMEOUT_SEC    = int(os.getenv("PROC_TIMEOUT_SEC", "3600"))

# 병렬 실행 워커 수(기본 6)
MODULE_MAX_WORKERS = int(os.getenv("MODULE_MAX_WORKERS", "6"))

# ── 공용 실행 유틸 ───────────────────────────────────────────────
def run_ps(cmd: str, timeout: Optional[int] = None):
    return subprocess.run(["powershell", "-NoProfile", "-Command", cmd],
                          capture_output=True, text=True, timeout=timeout)

def ps_lines(cp: subprocess.CompletedProcess):
    return [l.strip() for l in (cp.stdout or "").splitlines() if l.strip()]

def safe_run(func, *args, **kwargs):
    try:
        return func(*args, **kwargs)
    except SystemExit as se:
        print(f"[WARN] Caught SystemExit from child: {se}")
        return None
    except Exception as e:
        print(f"[ERR ] Exception in child: {e}")
        return None

# ── E01 자동 탐색 (여러 개여도 1개만 선택) ─────────────────────
def _existing_data_drives() -> List[str]:
    """
    C:를 제외한 실제 존재하는 드라이브 목록 (D:~Z:)
    """
    drives: List[str] = []
    for code in range(ord("D"), ord("Z") + 1):
        root = Path(f"{chr(code)}:\\")
        if root.exists():
            drives.append(chr(code))
    return drives

def _find_e01_candidates() -> List[Path]:
    """
    E01 후보 경로들을 전부 찾는다.
      1) E01_PATH가 가리키는 파일/폴더 우선
      2) 그 외에는 D:~Z: 전체에서 \ccit\*.e01 검색
    """
    candidates: List[Path] = []

    # 1) 환경변수 힌트 우선 (E01_PATH가 비어있지 않을 때만)
    if E01_PATH:
        p = Path(E01_PATH)
        if p.exists():
            if p.is_file() and p.suffix.lower() == ".e01":
                candidates.append(p)
            elif p.is_dir():
                try:
                    for hit in p.rglob("*.e01"):
                        candidates.append(hit)
                except Exception as e:
                    print(f"[WARN] 힌트 경로 rglob 실패: {p} ({e})")

    # 2) 아직 못 찾았으면 D:~Z: 각 드라이브의 \ccit\*.e01 검색
    if not candidates:
        drives = _existing_data_drives()
        if not drives:
            print("[ERR ] C 이외의 데이터 드라이브(D:~Z:)가 없습니다.")
            return []

        for d in drives:
            ccit_root = Path(f"{d}:\\ccit")
            if not ccit_root.is_dir():
                continue
            try:
                for hit in ccit_root.rglob("*.e01"):
                    candidates.append(hit)
            except Exception as e:
                print(f"[WARN] {ccit_root} 검색 중 예외 발생: {e}")

    return candidates

def resolve_e01_path() -> Optional[Path]:
    """
    전체 시스템에서 E01 이미지를 찾고, 그중 '딱 1개'만 선택해서 반환.
    여러 개 있으면 경고만 찍고 첫 번째만 사용.
    """
    candidates = _find_e01_candidates()
    if not candidates:
        print(f"[ERR ] E01 이미지 탐색 실패. 힌트={E01_PATH or '(없음)'}")
        return None

    # 정렬해서 고정된 순서 보장 (드라이브/경로 이름 기준)
    candidates = sorted(candidates, key=lambda p: (p.drive, str(p).lower()))

    if len(candidates) > 1:
        print("[WARN] E01 후보가 여러 개입니다. 첫 번째만 사용합니다:")
        for c in candidates:
            print(f"       - {c}")

    chosen = candidates[0]
    print(f"[INFO] 사용 E01: {chosen}")
    return chosen

# ── AIM helpers ───────────────────────────────────────────────────
def mount_e01(e01_path: Path):
    cmd = [AIM_EXE, "--mount", f"--filename={e01_path}", "--provider=LibEwf", "--readonly", "--online"]
    device_number = None
    disk_number = None
    try:
        proc = subprocess.Popen(cmd, stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True)
        start = time.time()
        assert proc.stdout
        for line in proc.stdout:
            line = line.strip()
            m_dev = re.search(r"Device number\s+(\d+)", line)
            if m_dev:
                device_number = m_dev.group(1)
            m_phy = re.search(r"Device is .*PhysicalDrive(\d+)", line, re.IGNORECASE)
            if m_phy:
                disk_number = int(m_phy.group(1))
            if "Mounted online" in line or "Mounted read only" in line:
                break
            if time.time() - start > 120:
                break
        time.sleep(MOUNT_STABILIZE_SEC)
        return disk_number, device_number
    except Exception as e:
        print(f"[ERR ] mount_e01 failed: {e}")
        return None, None

def get_ntfs_volumes(disk_number: int):
    ps = (
        f"Get-Partition -DiskNumber {disk_number} | Get-Volume | "
        f"Where-Object {{$_.FileSystem -eq 'NTFS'}} | Select-Object -ExpandProperty Path"
    )
    r = run_ps(ps, timeout=PS_TIMEOUT_SEC)
    vols = ps_lines(r)
    return [p if p.endswith('\\') else p + '\\' for p in vols if p.startswith('\\\\?\\Volume{')]

def get_letter_for_volume(vol_path: str):
    r = run_ps(
        f"Get-Volume | Where-Object {{$_.Path -eq '{vol_path}'}} | "
        f"Select-Object -ExpandProperty DriveLetter",
        timeout=PS_TIMEOUT_SEC
    )
    letter = (r.stdout or "").strip()
    return f"{letter}:" if letter else None

def dismount_e01(device_number=None):
    cmd = [AIM_EXE, f"--dismount={device_number}"] if device_number else [AIM_EXE, "--dismount=all"]
    try:
        subprocess.run(cmd, check=True, capture_output=True)
        print("[INFO] Dismounted.")
    except Exception as e:
        print(f"[WARN] Dismount error ignored: {e}")

# ── 베이스 디렉터리 / parser / tag 디렉터리 ──────────────────────
def _base_dir() -> Path:
    return Path(__file__).resolve().parent

def _parser_dir() -> Path:
    return _base_dir() / "parser"

def _tag_dir() -> Path:
    return _base_dir() / "tag"

# ── Target 복사(artifacts.py) ─────────────────────────────────────
def run_artifacts(letters: List[str], cfg: dict):
    """
    parser/artifacts.py의 run(drive_letters, unmount_callback, cfg)만
    선행으로 한 번 실행.
    """
    try:
        artifacts = importlib.import_module("parser.artifacts")
    except ImportError as e:
        print(f"[ERR] parser.artifacts import 실패: {e}")
        return

    if not hasattr(artifacts, "run"):
        print("[ERR] parser/artifacts.py에 run(drive_letters, unmount_callback, cfg) 함수가 필요합니다.")
        return

    print("[STEP] Target copy (parser.artifacts)")
    safe_run(artifacts.run, letters, (lambda: None), cfg)

# ── 모듈 시그니처 자동 감지 실행기 ───────────────────────────────
def _call_module_run(mod, letters: List[str], cfg: dict, name: str):
    """
    지원 시그니처:
      - run(drive_letters, cfg)
      - run(drive_letters, unmount, cfg)
      - run(cfg)
      - run()
    """
    if not hasattr(mod, "run"):
        print(f"[SKIP] {name}: run() 미구현")
        return

    fn = mod.run
    try:
        sig = inspect.signature(fn)
    except Exception:
        sig = None

    try:
        if sig:
            params = list(sig.parameters.keys())
            if len(params) >= 2 and params[0] != "cfg":
                # run(drive_letters, cfg) 또는 run(drive_letters, unmount, cfg)
                try:
                    fn(letters, cfg)
                except TypeError:
                    fn(letters, (lambda: None), cfg)
            elif len(params) >= 1 and params[0] == "cfg":
                # run(cfg)
                fn(cfg)
            else:
                # run()
                fn()
        else:
            try:
                fn(letters, cfg)
            except TypeError:
                try:
                    fn(letters, (lambda: None), cfg)
                except TypeError:
                    try:
                        fn(cfg)
                    except TypeError:
                        fn()
        print(f"[DONE] {name}")
    except SystemExit as se:
        print(f"[WARN] {name} raised SystemExit: {se}")
    except Exception as e:
        print(f"[ERR ] {name} 실행 오류: {e}")

# ── parser / tag 모듈 자동 탐색 ──────────────────────────────────
def _discover_modules(dir_path: Path, exclude: List[str] | None = None) -> List[str]:
    """
    주어진 디렉터리에서 *.py 모듈명을 찾아 리스트로 반환.
    exclude 리스트에 있는 이름(stem)은 제외.
    """
    if exclude is None:
        exclude = []
    if not dir_path.is_dir():
        return []

    names: List[str] = []
    for p in dir_path.glob("*.py"):
        stem = p.stem
        if stem.lower() in exclude:
            continue
        if stem.startswith("_"):
            continue
        names.append(stem)

    names.sort()
    return names

# ── 공용 모듈 실행기 (parser, tag 공용) ─────────────────────────
def _run_modules(package: str, module_names: List[str], letters: List[str], cfg: dict):
    """
    package: "parser" 또는 "tag"
    module_names: 실행할 모듈 이름(stem 리스트)
    """
    if not module_names:
        print(f"[INFO] 실행할 {package} 모듈이 없습니다.")
        return

    results: dict[str, str] = {}

    def _runner(name: str):
        full_name = f"{package}.{name}"
        try:
            mod = importlib.import_module(full_name)
        except ImportError as e:
            return name, f"[MISS] {full_name} import 실패: {e}"

        buf = [f"[STEP] {package}:{name}"]
        try:
            _call_module_run(mod, letters, cfg, f"{package}.{name}")
            buf.append(f"[DONE] {package}:{name}")
        except Exception as e:
            buf.append(f"[ERR ] {package}:{name} 실행 오류: {e}")
        return name, "\n".join(buf)

    with ThreadPoolExecutor(max_workers=MODULE_MAX_WORKERS) as ex:
        futs = {ex.submit(_runner, n): n for n in module_names}
        for fut in as_completed(futs):
            name, out = fut.result()
            results[name] = out

    # 요청 순서대로 출력
    for n in module_names:
        if n in results:
            print(results[n])

# ── parser 단계 실행 ─────────────────────────────────────────────
def run_parser_modules(letters: List[str], cfg: dict):
    """
    1) parser/artifacts.py 선행 실행
    2) parser 디렉터리 내 나머지 *.py 전부 실행
    """
    parser_dir = _parser_dir()

    # 1) artifacts 선행 실행
    run_artifacts(letters, cfg)

    # 2) 나머지 parser/*.py 자동 실행 (artifacts 제외)
    module_names = _discover_modules(parser_dir, exclude=["artifacts"])
    print(f"[INFO] parser 모듈 실행 대상: {', '.join(module_names) if module_names else '(없음)'}")
    _run_modules("parser", module_names, letters, cfg)

# ── tag 단계 실행 ────────────────────────────────────────────────
def run_tag_modules(letters: List[str], cfg: dict):
    """
    tag 디렉터리 내 *.py 전부 실행.
    (현재 tag 폴더가 비어 있으면 아무것도 하지 않음)
    """
    tag_dir = _tag_dir()
    module_names = _discover_modules(tag_dir, exclude=[])
    print(f"[INFO] tag 모듈 실행 대상: {', '.join(module_names) if module_names else '(없음)'}")
    _run_modules("tag", module_names, letters, cfg)

# ── main ──────────────────────────────────────────────────────────
def main():
    # 1) E01 자동 탐색(여러 개여도 1개만 선택)
    e01_resolved = resolve_e01_path()
    if not e01_resolved:
        return

    # 2) BASE_OUT(KAPE Output), TAG_OUT 결정
    #    기본: "E01이 있는 드라이브:\Kape Output" / "E01이 있는 드라이브:\tagged"
    if BASE_OUT_ENV:
        base_out = Path(BASE_OUT_ENV)
        drive = base_out.drive or (e01_resolved.drive or "D:")
    else:
        drive = e01_resolved.drive or "D:"
        base_out = Path(drive + r"\Kape Output")

    tag_out = Path(drive + r"\tagged")

    base_out.mkdir(parents=True, exist_ok=True)
    tag_out.mkdir(parents=True, exist_ok=True)

    # 3) E01 마운트
    disk, dev = mount_e01(e01_resolved)
    if disk is None:
        print("[ERR] AIM 마운트 실패")
        return

    try:
        # 4) NTFS 볼륨 → 드라이브 문자 매핑
        vols = get_ntfs_volumes(disk)
        letters = [get_letter_for_volume(v) for v in vols]
        letters = [l for l in letters if l]
        print(f"[INFO] NTFS 드라이브: {', '.join(letters) if letters else '(없음)'}")
        if not letters:
            print("[ERR ] NTFS 드라이브가 없어 종료")
            return

        cfg = {
            "BASE_OUT": base_out,          # KAPE Output 루트
            "KAPE_EXE": Path(KAPE_EXE),
            "PROC_TIMEOUT_SEC": PROC_TIMEOUT_SEC,
            "TAG_OUT": tag_out,            # 태깅 결과 루트 (tag/*.py에서 사용)
        }

        # 5) parser 단계: artifacts → 나머지 파서 전부 실행
        #run_parser_modules(letters, cfg)

        # 6) tag 단계: tag 폴더 내 태깅 모듈 전부 실행
        run_tag_modules(letters, cfg)

    except Exception as e:
        print(f"[FATAL] main 실패: {e}")
    finally:
        dismount_e01(dev)

if __name__ == "__main__":
    main()
