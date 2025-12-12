import re
from pathlib import Path
from typing import Iterator, List, Optional, Tuple

import pandas as pd


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
# MFTTagger (원본 로직 유지)
# ============================================================

class MFTTagger:
    """
    MFTECmd CSV → 1차 태깅 CSV (Windows 포렌식 태깅 체계 연동)
    (중간 로직은 그대로, 경로 스캔/출력만 통일)
    """

    def __init__(self, infer_event: bool = True, infer_activity: bool = True):
        self.infer_event = infer_event
        self.infer_activity = infer_activity

        self.now = pd.Timestamp.now()
        self.one_day_ago = self.now - pd.Timedelta(days=1)
        self.one_week_ago = self.now - pd.Timedelta(days=7)
        self.one_month_ago = self.now - pd.Timedelta(days=30)

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

        self.suspicious_name_patterns = [
            r"mimikatz", r"procdump", r"psexec", r"cobalt", r"beacon",
            r"keygen", r"crack", r"payload", r"backdoor", r"ransom",
        ]

    def _norm_path(self, p: str) -> str:
        p = (p or "").strip()
        p = p.replace("/", "\\").lower()
        p = re.sub(r"\\{2,}", r"\\", p)
        return p

    def _safe_ext(self, ext: str) -> str:
        ext = (ext or "").strip().lower()
        if not ext:
            return ""
        if not ext.startswith("."):
            ext = "." + ext
        return ext

    def _pick_first_existing(self, row: pd.Series, cols: List[str]):
        for c in cols:
            if c in row.index and pd.notna(row[c]) and str(row[c]).strip() != "":
                return row[c]
        return None

    def _real_ts(self, v) -> Optional[pd.Timestamp]:
        if v is None or pd.isna(v) or str(v).strip() == "":
            return None
        ts = pd.to_datetime(v, errors="coerce")
        if ts is pd.NaT:
            return None
        if ts.year <= 1601:
            return None
        return ts

    def get_time_bucket(self, ts_raw) -> Optional[str]:
        ts = self._real_ts(ts_raw)
        if ts is None:
            return None
        if ts >= self.one_day_ago:
            return "TIME_RECENT"
        if ts >= self.one_week_ago:
            return "TIME_WEEK"
        if ts >= self.one_month_ago:
            return "TIME_MONTH"
        return "TIME_OLD"

    def get_time_presence_tags(self, row: pd.Series, kind: str) -> List[str]:
        tags: List[str] = []

        created = self._real_ts(self._pick_first_existing(row, ["Created0x10", "CreationTime", "Created", "CreatedUtc"]))
        modified = self._real_ts(self._pick_first_existing(row, ["LastModified0x10", "LastWriteTime", "LastWrite", "Modified", "ModifiedUtc"]))
        accessed = self._real_ts(self._pick_first_existing(row, ["LastAccess0x10", "LastAccessTime", "Accessed", "AccessedUtc"]))

        if created:
            tags.append("TIME_CREATED")
        if modified:
            tags.append("TIME_MODIFIED")
        if accessed:
            tags.append("TIME_ACCESSED")

        if kind == "MFT_ENTRY":
            si_any = self._real_ts(self._pick_first_existing(
                row, ["Created0x10", "LastModified0x10", "LastAccess0x10", "LastRecordChange0x10"]
            ))
            fn_any = self._real_ts(self._pick_first_existing(
                row, ["Created0x30", "LastModified0x30", "LastAccess0x30", "LastRecordChange0x30"]
            ))
            if si_any:
                tags.append("TIME_MFT_CREATED")
            if fn_any:
                tags.append("TIME_FN_CREATED")

        return list(dict.fromkeys(tags))

    def get_area_tags(self, path: str) -> List[str]:
        p = self._norm_path(path)
        if not p:
            return []

        tags: List[str] = []

        if re.match(r"^[d-z]:\\", p):
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
            if "\\downloads\\" in p:
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

    def get_state_tags(self, row: pd.Series) -> List[str]:
        tags: List[str] = []

        if row.get("InUse") in [1, True, "True", "true"]:
            tags.append("STATE_ACTIVE")
        elif row.get("InUse") in [0, False, "False", "false"]:
            tags.append("STATE_DELETED")

        attrs = str(row.get("Attributes", "") or "").lower()
        if attrs:
            if "hidden" in attrs:
                tags.append("STATE_HIDDEN")
            if "readonly" in attrs or "read-only" in attrs:
                tags.append("STATE_READONLY")
            if "system" in attrs:
                tags.append("STATE_SYSTEM")

        return list(dict.fromkeys(tags))

    def get_sec_tags(self, path: str, filename: str, ext: str,
                     format_tags: List[str], area_tags: List[str], state_tags: List[str]) -> List[str]:
        tags: List[str] = []
        p = self._norm_path(path)
        name = (filename or "").lower()

        if "FORMAT_EXECUTABLE" in format_tags:
            tags.append("SEC_EXECUTABLE")
        if "FORMAT_SCRIPT" in format_tags:
            tags.append("SEC_SCRIPT")

        if "STATE_HIDDEN" in state_tags and "FORMAT_EXECUTABLE" in format_tags:
            tags.append("SEC_HIDDEN_EXECUTABLE")

        for pat in self.suspicious_name_patterns:
            if re.search(pat, name, re.IGNORECASE):
                tags.append("SEC_SUSPICIOUS_NAME")
                break

        if name.count(".") >= 2:
            parts = name.split(".")
            last = "." + parts[-1]
            prev = "." + parts[-2]
            if last in (self.exec_ext | self.script_ext) and prev in (self.doc_ext | self.img_ext):
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

    def get_event_tags(self, state_tags: List[str], row: pd.Series) -> List[str]:
        if not self.infer_event:
            return []
        tags: List[str] = []
        if "STATE_DELETED" in state_tags:
            tags.append("EVENT_DELETE")

        created_raw = self._pick_first_existing(row, ["Created0x10", "CreationTime", "Created", "CreatedUtc"])
        modified_raw = self._pick_first_existing(row, ["LastModified0x10", "LastWriteTime", "LastWrite", "Modified", "ModifiedUtc"])

        if self._real_ts(created_raw) is not None:
            if self.get_time_bucket(created_raw) in ("TIME_RECENT", "TIME_WEEK"):
                tags.append("EVENT_CREATE")

        if self._real_ts(modified_raw) is not None:
            if self.get_time_bucket(modified_raw) in ("TIME_RECENT", "TIME_WEEK"):
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

    def detect_kind(self, csv_name: str) -> str:
        name = csv_name.lower()

        if "_mft_dumpresidentfiles" in name:
            return "MFT_DUMP_RESIDENT"
        if "_filelisting" in name:
            return "MFT_FILE_LISTING"
        if "_mft_output" in name or "_mft_" in name or "$mft" in name:
            return "MFT_ENTRY"

        if "usnjrnl" in name or "$j" in name or "_$j" in name:
            return "IGNORE"
        if "_boot" in name or "$boot" in name:
            return "IGNORE"

        return "IGNORE"

    def build_description(self, row: pd.Series, fields: List[str]) -> str:
        out = []
        for col in fields:
            if col in row.index and pd.notna(row[col]) and str(row[col]).strip() != "":
                out.append(f"{col}: {row[col]}")
        return " | ".join(out)

    def tag_row(self, row: pd.Series, kind: str) -> Tuple[str, Optional[str], str]:
        tags: List[str] = ["ARTIFACT_MFT"]

        if kind == "MFT_ENTRY":
            path = row.get("ParentPath", "") or ""
            filename = row.get("FileName", "") or ""
            ext = row.get("Extension", "") or ""
            lastwrite_raw = self._pick_first_existing(
                row, ["LastModified0x10", "LastWriteTime", "LastWrite", "Modified", "ModifiedUtc"]
            )
            desc_fields = ["ParentPath", "FileName", "Extension", "FileSize", "InUse"]

        elif kind == "MFT_FILE_LISTING":
            path = row.get("FullPath", "") or ""
            filename = Path(str(path)).name if path else (row.get("FileName", "") or "")
            ext = row.get("Extension", "") or Path(str(filename)).suffix
            lastwrite_raw = self._pick_first_existing(
                row, ["LastWriteTime", "LastWrite", "Modified", "ModifiedUtc", "LastModified0x10"]
            )
            desc_fields = ["FullPath", "Extension", "IsDirectory", "FileSize"]

        else:  # MFT_DUMP_RESIDENT
            path = row.get("LocalPath", "") or row.get("RelativePath", "") or ""
            filename = Path(str(path)).name if path else (row.get("FileName", "") or "")
            ext = Path(str(filename)).suffix
            lastwrite_raw = self._pick_first_existing(
                row, ["TargetModified", "SourceModified", "TargetCreated", "SourceCreated"]
            )
            desc_fields = ["RelativePath", "LocalPath", "FileSize", "DriveType"]

        npath = self._norm_path(str(path))
        ext = self._safe_ext(str(ext))

        tb = self.get_time_bucket(lastwrite_raw)
        if tb:
            tags.append(tb)
        tags += self.get_time_presence_tags(row, kind)

        area_tags = self.get_area_tags(npath)
        tags += area_tags

        format_tags = self.get_format_tags(ext)
        tags += format_tags

        state_tags = self.get_state_tags(row)
        tags += state_tags

        sec_tags = self.get_sec_tags(npath, str(filename), ext, format_tags, area_tags, state_tags)
        tags += sec_tags

        tags += self.get_event_tags(state_tags, row)
        tags += self.get_activity_tags(area_tags, format_tags, sec_tags)

        desc = self.build_description(row, desc_fields)

        tags_clean: List[str] = []
        for t in tags:
            if not t:
                continue
            t = str(t).strip()
            if t:
                tags_clean.append(t)

        tags_str = " | ".join(dict.fromkeys(tags_clean))
        return tags_str, lastwrite_raw, desc

    def process_csv(self, csv_path: Path, output_root: Path, case_name: str) -> Tuple[Optional[str], int]:
        csv_path = Path(csv_path)
        df = pd.read_csv(csv_path, low_memory=False)

        kind = self.detect_kind(csv_path.name)
        if kind == "IGNORE":
            print(f"  → 스킵됨 (Boot/USN$J/Unknown): {csv_path.name}")
            return None, 0

        out_rows = []
        for _, row in df.iterrows():
            tags, ts_raw, desc = self.tag_row(row, kind)
            out_rows.append({
                "Type": kind,
                "LastWriteTimestamp": ts_raw,
                "description": desc,
                "Tags": tags,
            })

        out_df = pd.DataFrame(out_rows)

        output_root.mkdir(exist_ok=True, parents=True)
        safe_case = sanitize_for_filename(case_name)
        out_csv = ensure_unique_output_path(output_root / f"{csv_path.stem}_{safe_case}_tagged.csv")

        out_df.to_csv(out_csv, index=False, encoding="utf-8-sig")
        return str(out_csv), len(out_rows)


# ============================================================
# 실행 (D~Z 스캔)
# ============================================================

if __name__ == "__main__":
    tagger = MFTTagger(infer_event=True, infer_activity=True)
    total = 0

    for drive_root, case_name, case_dir in iter_case_dirs(debug=False):
        output_root = drive_root / "tagged"
        output_root.mkdir(parents=True, exist_ok=True)

        csv_files = []
        for p in case_dir.rglob("*MFTECmd_*.csv"):
            n = p.name.lower()
            if "_tagged" in n:
                continue
            # Boot는 Boot 전용 스크립트가 처리
            if "boot" in n:
                continue
            csv_files.append(p)

        if not csv_files:
            continue

        print(f"\n[{drive_root}] case={case_name} | MFTECmd {len(csv_files)}개")

        for i, csv_path in enumerate(csv_files, start=1):
            print(f"[{i}/{len(csv_files)}] 처리 중: {csv_path}")
            try:
                out_csv, cnt = tagger.process_csv(csv_path, output_root, case_name)
                if out_csv:
                    print(f"  → 완료: {out_csv} ({cnt}행)")
                    total += 1
                else:
                    print("  → 스킵됨")
            except Exception as e:
                print(f"  오류: {e}")

    print("\n=== MFTCmd done:", total, "===")
