import csv
import re
import time
from pathlib import Path
from typing import Dict, Iterator, List, Optional, Tuple
from datetime import datetime, timedelta


# ============================================================
# 공통 유틸 (D~Z:\Kape Output\<case>\...)
# ============================================================

def iter_case_dirs(debug: bool = False) -> Iterator[tuple[Path, str, Path]]:
    for code in range(ord("D"), ord("Z") + 1):
        drive_root = Path(f"{chr(code)}:/")
        kape_root = drive_root / "Kape Output"

        if debug and chr(code).upper() == "D":
            print("[DEBUG] drive_root =", drive_root)
            print("[DEBUG] kape_root  =", kape_root)
            print("[DEBUG] exists/is_dir =", kape_root.exists(), kape_root.is_dir())

        if not kape_root.is_dir():
            continue

        case_dirs = [p for p in kape_root.iterdir() if p.is_dir()]

        if debug and chr(code).upper() == "D":
            print(f"[DEBUG] found cases in {kape_root}: {[p.name for p in case_dirs]}")

        for case_dir in case_dirs:
            yield drive_root, case_dir.name, case_dir


def ensure_unique_output_path(path: Path) -> Path:
    if not path.exists():
        return path
    parent, stem, suffix = path.parent, path.stem, path.suffix
    i = 1
    while True:
        cand = parent / f"{stem}_{i}{suffix}"
        if not cand.exists():
            return cand
        i += 1


def sanitize_for_filename(s: str) -> str:
    return re.sub(r'[\\/:*?"<>|]', "_", str(s)).strip()


# ============================================================
# Fast MFT Tagger (스트리밍 + 시간측정)
# ============================================================

class FastMFTTagger:
    """
    MFTECmd CSV → 1차 태깅 CSV (초고속 스트리밍)
    - pandas 미사용
    - csv.reader 스트리밍 처리(메모리 고정)
    - datetime.fromisoformat 기반 빠른 시간 파싱(100ns 소수부 자동 절삭)
    - Tags에는 kind(MFT_FILE_LISTING 등) 넣지 않음 (Type 컬럼에 이미 있음)
    - STATE_DIRECTORY 없음 (폴더 여부는 description의 IsDirectory로만 표현)
    """

    def __init__(self, infer_event: bool = True, infer_activity: bool = True):
        self.infer_event = infer_event
        self.infer_activity = infer_activity

        now = datetime.now()
        self.one_day_ago = now - timedelta(days=1)
        self.one_week_ago = now - timedelta(days=7)
        self.one_month_ago = now - timedelta(days=30)

        # FORMAT/SEC 확장자
        self.exec_ext = {".exe", ".dll", ".sys", ".scr", ".com"}
        self.script_ext = {".ps1", ".bat", ".cmd", ".vbs", ".js", ".py", ".psm1", ".hta"}
        self.doc_ext = {".txt", ".rtf", ".pdf", ".doc", ".docx", ".hwp", ".odt"}
        self.sheet_ext = {".xls", ".xlsx", ".csv"}
        self.ppt_ext = {".ppt", ".pptx"}
        self.img_ext = {".jpg", ".jpeg", ".png", ".gif", ".bmp", ".ico", ".svg", ".webp"}
        self.video_ext = {".mp4", ".avi", ".mkv", ".mov", ".wmv"}
        self.audio_ext = {".mp3", ".wav", ".flac", ".wma", ".aac", ".ogg"}
        self.archive_ext = {".zip", ".rar", ".7z", ".tar", ".gz", ".bz2", ".xz"}
        self.db_ext = {".db", ".sqlite", ".accdb", ".mdb"}

        # 의심 파일명(속도 위해 substring)
        self.suspicious_name_tokens = [
            "mimikatz", "procdump", "psexec", "cobalt", "beacon",
            "keygen", "crack", "payload", "backdoor", "ransom",
        ]

        # 시간 컬럼 후보(환경 차이 대비)
        self.CREATED_COLS = [
            "Created0x10", "CreationTime", "Created", "CreatedUtc", "CreatedUTC",
            "CreatedTime", "CreatedTimeUtc", "CreatedTimeUTC",
            "CreatedTimestamp", "CreationTimestamp",
        ]
        self.MODIFIED_COLS = [
            "LastModified0x10", "LastWriteTime", "LastWrite", "Modified", "ModifiedUtc", "ModifiedUTC",
            "LastWriteTimestamp", "LastWriteTimestampUtc", "LastWriteTimestampUTC",
        ]
        self.ACCESSED_COLS = [
            "LastAccess0x10", "LastAccessTime", "Accessed", "AccessedUtc", "AccessedUTC",
            "LastAccessTimestamp", "LastAccessTimestampUtc", "LastAccessTimestampUTC",
        ]

        # kind별 “버킷용 LastWrite 후보”
        self.LASTWRITE_COLS = {
            "MFT_ENTRY": ["LastModified0x10", "LastWriteTime", "LastWrite", "Modified", "ModifiedUtc", "LastWriteTimestamp"],
            "MFT_FILE_LISTING": ["LastWriteTimestamp", "LastWriteTime", "LastWrite", "Modified", "ModifiedUtc", "LastModified0x10"],
            "MFT_DUMP_RESIDENT": ["TargetModified", "SourceModified", "TargetCreated", "SourceCreated"],
        }

        # 100ns(7자리) 이상 소수부 → 6자리 절삭
        self._frac_re = re.compile(r"^(.*\.\d{6})\d+(.*)$")

    # -----------------------------
    # KIND 판별
    # -----------------------------
    def detect_kind(self, csv_name: str) -> str:
        n = csv_name.lower()

        if "_mft_dumpresidentfiles" in n:
            return "MFT_DUMP_RESIDENT"
        if "_filelisting" in n:
            return "MFT_FILE_LISTING"
        if "_mft_output" in n or "_mft_" in n or "$mft" in n:
            return "MFT_ENTRY"

        # USN $J / Boot는 별도 태거로
        if "usnjrnl" in n or "$j" in n or "_$j" in n:
            return "IGNORE"
        if "_boot" in n or "$boot" in n:
            return "IGNORE"

        return "IGNORE"

    # -----------------------------
    # 빠른 값 접근
    # -----------------------------
    def _get(self, row: List[str], idx: Dict[str, int], col: str) -> str:
        i = idx.get(col, -1)
        if i < 0 or i >= len(row):
            return ""
        v = row[i]
        return v if v is not None else ""

    def _pick(self, row: List[str], idx: Dict[str, int], cols: List[str]) -> str:
        for c in cols:
            v = self._get(row, idx, c)
            if v and str(v).strip() != "":
                return v
        return ""

    # -----------------------------
    # 시간 파싱/정규화
    # -----------------------------
    def _real_dt(self, v: str) -> Optional[datetime]:
        if not v:
            return None
        s = str(v).strip()
        if not s:
            return None

        m = self._frac_re.match(s)
        if m:
            s = m.group(1) + m.group(2)

        if s.endswith("Z"):
            s = s[:-1]

        try:
            dt = datetime.fromisoformat(s)
        except Exception:
            return None

        if dt.year <= 1601:
            return None
        return dt

    def get_time_bucket(self, dt: Optional[datetime]) -> Optional[str]:
        if dt is None:
            return None
        if dt >= self.one_day_ago:
            return "TIME_RECENT"
        if dt >= self.one_week_ago:
            return "TIME_WEEK"
        if dt >= self.one_month_ago:
            return "TIME_MONTH"
        return "TIME_OLD"

    def get_time_presence_tags(self, row: List[str], idx: Dict[str, int], kind: str) -> List[str]:
        tags: List[str] = []

        created = self._real_dt(self._pick(row, idx, self.CREATED_COLS))
        modified = self._real_dt(self._pick(row, idx, self.MODIFIED_COLS))
        accessed = self._real_dt(self._pick(row, idx, self.ACCESSED_COLS))

        if created:
            tags.append("TIME_CREATED")
        if modified:
            tags.append("TIME_MODIFIED")
        if accessed:
            tags.append("TIME_ACCESSED")

        # ✅ MFT 구조 기반 태그는 MFT_ENTRY에서만
        if kind == "MFT_ENTRY":
            si_any = self._real_dt(self._pick(row, idx, ["Created0x10", "LastModified0x10", "LastAccess0x10", "LastRecordChange0x10"]))
            fn_any = self._real_dt(self._pick(row, idx, ["Created0x30", "LastModified0x30", "LastAccess0x30", "LastRecordChange0x30"]))
            if si_any:
                tags.append("TIME_MFT_CREATED")
            if fn_any:
                tags.append("TIME_FN_CREATED")

        return tags

    # -----------------------------
    # 경로/확장자
    # -----------------------------
    def _norm_path(self, p: str) -> str:
        p = (p or "").strip().replace("/", "\\").lower()
        p = re.sub(r"\\{2,}", r"\\", p)
        return p

    def _safe_ext(self, ext: str) -> str:
        ext = (ext or "").strip().lower()
        if not ext:
            return ""
        if not ext.startswith("."):
            ext = "." + ext
        return ext

    def get_area_tags(self, path: str) -> List[str]:
        p = self._norm_path(path)
        if not p:
            return []
        tags: List[str] = []

        if len(p) >= 3 and p[1:3] == ":\\" and "d" <= p[0] <= "z":
            tags.append("AREA_EXTERNAL_DRIVE")

        if "\\windows\\system32" in p or "\\windows\\syswow64" in p:
            tags.append("AREA_SYSTEM32")
        if "\\windows\\" in p or p.startswith("c:\\windows"):
            tags.append("AREA_WINDOWS")

        if "\\windows\\prefetch" in p:
            tags.append("AREA_PREFETCH")
        if "\\windows\\temp" in p or "\\temp\\" in p or p.endswith("\\temp"):
            tags.append("AREA_TEMP")
        if "\\$recycle.bin" in p:
            tags.append("AREA_RECYCLE_BIN")
        if "\\system volume information" in p:
            tags.append("AREA_VSS")

        if p.startswith("c:\\program files") or "\\program files\\" in p:
            tags.append("AREA_PROGRAMFILES")
        if p.startswith("c:\\programdata") or "\\programdata\\" in p:
            tags.append("AREA_PROGRAMDATA")

        if "\\users\\" in p:
            if "\\desktop" in p:
                tags.append("AREA_USER_DESKTOP")
            if "\\documents" in p:
                tags.append("AREA_USER_DOCUMENTS")
            if "\\downloads\\" in p or p.endswith("\\downloads"):
                tags.append("AREA_USER_DOWNLOADS")
            if "\\recent" in p:
                tags.append("AREA_USER_RECENT")
            if "\\appdata\\local\\" in p:
                tags.append("AREA_APPDATA_LOCAL")
            if "\\appdata\\roaming\\" in p:
                tags.append("AREA_APPDATA_ROAMING")
            if "\\appdata\\locallow\\" in p:
                tags.append("AREA_APPDATA_LOCALLOW")

        if "\\start menu\\programs\\startup" in p or "\\startup\\" in p or p.endswith("\\startup"):
            tags.append("AREA_STARTUP")

        if p.startswith("\\\\") or p.startswith("\\\\?\\unc\\") or "\\unc\\" in p:
            tags.append("AREA_NETWORK_SHARE")

        return list(dict.fromkeys(tags))

    def get_format_tags(self, ext: str) -> List[str]:
        e = self._safe_ext(ext)
        if not e:
            return []
        if e in self.exec_ext:
            return ["FORMAT_EXECUTABLE"]
        if e in self.script_ext:
            return ["FORMAT_SCRIPT"]
        if e in self.doc_ext:
            return ["FORMAT_DOCUMENT"]
        if e in self.sheet_ext:
            return ["FORMAT_SPREADSHEET"]
        if e in self.ppt_ext:
            return ["FORMAT_PRESENTATION"]
        if e in self.img_ext:
            return ["FORMAT_IMAGE"]
        if e in self.video_ext:
            return ["FORMAT_VIDEO"]
        if e in self.audio_ext:
            return ["FORMAT_AUDIO"]
        if e in self.archive_ext:
            return ["FORMAT_ARCHIVE"]
        if e in self.db_ext:
            return ["FORMAT_DATABASE"]
        return []

    # -----------------------------
    # STATE_ (STATE_DIRECTORY 없음)
    # -----------------------------
    def get_state_tags(self, row: List[str], idx: Dict[str, int]) -> List[str]:
        tags: List[str] = []
        inuse = (self._get(row, idx, "InUse") or "").strip().lower()

        if inuse in ("1", "true", "yes"):
            tags.append("STATE_ACTIVE")
        elif inuse in ("0", "false", "no"):
            tags.append("STATE_DELETED")

        attrs = (self._get(row, idx, "Attributes") or "").strip().lower()
        if attrs:
            if "hidden" in attrs:
                tags.append("STATE_HIDDEN")
            if "readonly" in attrs or "read-only" in attrs:
                tags.append("STATE_READONLY")
            if "system" in attrs:
                tags.append("STATE_SYSTEM")

        return list(dict.fromkeys(tags))

    # -----------------------------
    # SEC_
    # -----------------------------
    def get_sec_tags(
        self,
        path: str,
        filename: str,
        format_tags: List[str],
        area_tags: List[str],
        state_tags: List[str],
    ) -> List[str]:
        tags: List[str] = []
        p = self._norm_path(path)
        name = (filename or "").strip().lower()

        if "FORMAT_EXECUTABLE" in format_tags:
            tags.append("SEC_EXECUTABLE")
        if "FORMAT_SCRIPT" in format_tags:
            tags.append("SEC_SCRIPT")
        if "STATE_HIDDEN" in state_tags and "FORMAT_EXECUTABLE" in format_tags:
            tags.append("SEC_HIDDEN_EXECUTABLE")

        if name:
            for tok in self.suspicious_name_tokens:
                if tok in name:
                    tags.append("SEC_SUSPICIOUS_NAME")
                    break

            if name.count(".") >= 2:
                parts = name.split(".")
                last = "." + parts[-1]
                prev = "." + parts[-2]
                if (last in (self.exec_ext | self.script_ext)) and (prev in (self.doc_ext | self.img_ext)):
                    tags.append("SEC_SUSPICIOUS_EXTENSION")

        if ("AREA_USER_DOWNLOADS" in area_tags or "AREA_TEMP" in area_tags) and (
            "FORMAT_EXECUTABLE" in format_tags or "FORMAT_SCRIPT" in format_tags
        ):
            tags.append("SEC_SUSPICIOUS_PATH")

        if "AREA_STARTUP" in area_tags and ("FORMAT_EXECUTABLE" in format_tags or "FORMAT_SCRIPT" in format_tags):
            tags.append("SEC_PERSISTENCE_STARTUP")

        if "\\windows\\system32\\tasks" in p:
            tags.append("SEC_PERSISTENCE_TASK")

        return list(dict.fromkeys(tags))

    # -----------------------------
    # EVENT_ / ACT_ (추정)
    # -----------------------------
    def get_event_tags(self, row: List[str], idx: Dict[str, int], state_tags: List[str]) -> List[str]:
        if not self.infer_event:
            return []
        tags: List[str] = []

        if "STATE_DELETED" in state_tags:
            tags.append("EVENT_DELETE")

        created_dt = self._real_dt(self._pick(row, idx, self.CREATED_COLS))
        modified_dt = self._real_dt(self._pick(row, idx, self.MODIFIED_COLS))

        if created_dt and self.get_time_bucket(created_dt) in ("TIME_RECENT", "TIME_WEEK"):
            tags.append("EVENT_CREATE")
        if modified_dt and self.get_time_bucket(modified_dt) in ("TIME_RECENT", "TIME_WEEK"):
            tags.append("EVENT_MODIFY")

        return list(dict.fromkeys(tags))

    def get_activity_tags(self, area_tags: List[str], format_tags: List[str], sec_tags: List[str]) -> List[str]:
        if not self.infer_activity:
            return []
        tags: List[str] = []

        if "AREA_USER_DOWNLOADS" in area_tags and (
            "FORMAT_DOCUMENT" in format_tags or "FORMAT_ARCHIVE" in format_tags or "FORMAT_EXECUTABLE" in format_tags
        ):
            tags.append("ACT_DOWNLOAD")

        if "AREA_NETWORK_SHARE" in area_tags:
            tags.append("ACT_NETWORK_ACCESS")

        if "SEC_PERSISTENCE_STARTUP" in sec_tags:
            tags.append("ACT_INSTALL")

        if area_tags or format_tags:
            tags.append("ACT_FILE_OPERATION")

        return list(dict.fromkeys(tags))

    # -----------------------------
    # description
    # -----------------------------
    def build_description(self, row: List[str], idx: Dict[str, int], fields: List[str]) -> str:
        parts = []
        for f in fields:
            v = self._get(row, idx, f)
            if v and str(v).strip() != "":
                parts.append(f"{f}: {v}")
        return " | ".join(parts)

    # -----------------------------
    # 한 줄 처리
    # -----------------------------
    def tag_one(self, row: List[str], idx: Dict[str, int], kind: str) -> Tuple[str, str, str]:
        tags: List[str] = ["ARTIFACT_MFT"]  # ✅ kind는 Tags에 넣지 않음

        if kind == "MFT_ENTRY":
            path = self._get(row, idx, "ParentPath")
            filename = self._get(row, idx, "FileName")
            ext = self._get(row, idx, "Extension")
            desc_fields = ["ParentPath", "FileName", "Extension", "FileSize", "InUse"]

        elif kind == "MFT_FILE_LISTING":
            path = self._get(row, idx, "FullPath")
            filename = (path.split("\\")[-1] if path else self._get(row, idx, "FileName"))
            ext = self._get(row, idx, "Extension")
            desc_fields = ["FullPath", "Extension", "IsDirectory", "FileSize"]

        else:  # MFT_DUMP_RESIDENT
            path = self._get(row, idx, "LocalPath") or self._get(row, idx, "RelativePath")
            filename = (path.split("\\")[-1] if path else self._get(row, idx, "FileName"))
            ext = ""
            desc_fields = ["RelativePath", "LocalPath", "FileSize", "DriveType"]

        npath = self._norm_path(path)
        ext = self._safe_ext(ext)

        last_raw = self._pick(row, idx, self.LASTWRITE_COLS.get(kind, []))
        last_dt = self._real_dt(last_raw)

        tb = self.get_time_bucket(last_dt)
        if tb:
            tags.append(tb)

        tags += self.get_time_presence_tags(row, idx, kind)

        area_tags = self.get_area_tags(npath)
        tags += area_tags

        format_tags = self.get_format_tags(ext)
        tags += format_tags

        state_tags = self.get_state_tags(row, idx)
        tags += state_tags

        sec_tags = self.get_sec_tags(npath, filename, format_tags, area_tags, state_tags)
        tags += sec_tags

        tags += self.get_event_tags(row, idx, state_tags)
        tags += self.get_activity_tags(area_tags, format_tags, sec_tags)

        desc = self.build_description(row, idx, desc_fields)

        # ✅ 공백/중복 제거
        cleaned = []
        seen = set()
        for t in tags:
            t = (t or "").strip()
            if not t or t in seen:
                continue
            seen.add(t)
            cleaned.append(t)

        return " | ".join(cleaned), last_raw, desc

    # -----------------------------
    # 파일 처리(스트리밍 + 시간측정 + 진행로그)
    # output_root: <drive>:\tagged
    # output name: <stem>_<case>_tagged.csv
    # -----------------------------
    def process_csv(
        self,
        csv_path: Path,
        output_root: Path,
        case_name: str,
        progress_every: int = 200_000,
    ) -> Tuple[Optional[str], int, float]:
        csv_path = Path(csv_path)
        kind = self.detect_kind(csv_path.name)

        if kind == "IGNORE":
            print(f"  → 스킵됨 (Boot/USN$J/Unknown): {csv_path.name}")
            return None, 0, 0.0

        output_root.mkdir(parents=True, exist_ok=True)

        safe_case = sanitize_for_filename(case_name)
        out_file = ensure_unique_output_path(
            output_root / f"{csv_path.stem}_{safe_case}_tagged.csv"
        )

        def _open_with_fallback(p: Path):
            try:
                return p.open("r", encoding="utf-8-sig", newline="")
            except UnicodeDecodeError:
                return p.open("r", encoding="cp949", errors="ignore", newline="")

        t0 = time.perf_counter()
        last_tick = t0
        total = 0

        with _open_with_fallback(csv_path) as f_in, out_file.open("w", encoding="utf-8-sig", newline="") as f_out:
            reader = csv.reader(f_in)
            writer = csv.writer(f_out)

            header = next(reader, None)
            if not header:
                return str(out_file), 0, 0.0

            idx = {col: i for i, col in enumerate(header)}
            writer.writerow(["Type", "LastWriteTimestamp", "description", "Tags"])

            for row in reader:
                if not row or len(row) < 2:
                    continue

                tags, ts_raw, desc = self.tag_one(row, idx, kind)
                writer.writerow([kind, ts_raw, desc, tags])
                total += 1

                if progress_every and total % progress_every == 0:
                    now = time.perf_counter()
                    chunk_dt = now - last_tick
                    elapsed = now - t0
                    rps = (progress_every / chunk_dt) if chunk_dt > 0 else 0.0
                    print(f"    ... {total:,} rows | +{chunk_dt:.2f}s | {rps:,.0f} rows/s | elapsed {elapsed:.1f}s")
                    last_tick = now

        dt = time.perf_counter() - t0
        return str(out_file), total, dt


# ============================================================
# 실행 (WxTActivityTagger와 동일한 경로 규칙)
# ============================================================

if __name__ == "__main__":
    tagger = FastMFTTagger(infer_event=True, infer_activity=True)
    total_files = 0
    total_rows = 0

    grand_t0 = time.perf_counter()

    for drive_root, case_name, case_dir in iter_case_dirs(debug=False):
        # ✅ 출력 루트: <drive>:\tagged (단일 폴더)
        output_root = drive_root / "tagged"
        output_root.mkdir(parents=True, exist_ok=True)

        csv_files: List[Path] = []
        for p in case_dir.rglob("*.csv"):
            n = p.name.lower()
            # ✅ 재처리 방지
            if "_tagged" in n or "_normalized" in n:
                continue
            # ✅ MFTECmd만
            if "mftecmd_" not in n:
                continue
            csv_files.append(p)

        if not csv_files:
            continue

        print(f"\n[{drive_root}] case={case_name} | MFTECmd {len(csv_files)}개")

        for i, csv_path in enumerate(csv_files, 1):
            print(f"[{i}/{len(csv_files)}] 처리 중: {csv_path}")
            try:
                out, cnt, dt = tagger.process_csv(
                    csv_path=csv_path,
                    output_root=output_root,
                    case_name=case_name,
                    progress_every=200_000,
                )
                if out:
                    rps = (cnt / dt) if dt > 0 else 0.0
                    print(f"  → 완료: {out}")
                    print(f"     rows={cnt:,} | time={dt:.2f}s | speed={rps:,.0f} rows/s\n")
                    total_files += 1
                    total_rows += cnt
                else:
                    print("  → 스킵됨\n")
            except Exception as e:
                print(f"[ERR] {csv_path} → {e}\n")

    grand_dt = time.perf_counter() - grand_t0
    grand_rps = (total_rows / grand_dt) if grand_dt > 0 else 0.0

    print("\n=== MFTECmd done ===")
    print(f"files={total_files:,} | rows={total_rows:,} | time={grand_dt:.2f}s | speed={grand_rps:,.0f} rows/s")
