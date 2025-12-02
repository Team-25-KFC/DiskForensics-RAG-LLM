import pandas as pd
import re
from datetime import datetime, timedelta
from pathlib import Path


class MFTTagger:
    """
    MFTECmd CSV를 1차 자동 태깅해서
    Type / LastWriteTimestamp / description / Tags 형태의 JSONL로 축소
    """

    def __init__(self):
        self.now = datetime.now()
        self.one_day_ago = self.now - timedelta(days=1)
        self.one_week_ago = self.now - timedelta(days=7)
        self.one_month_ago = self.now - timedelta(days=30)

        # SEC_SUSPICIOUS_NAME 용 이름 패턴
        self.suspicious_name_patterns = [
            r"crack",
            r"keygen",
            r"payload",
            r"backdoor",
            r"mimikatz",
            r"psexec",
            r"procdump",
            r"dump",
            r"inject",
            r"exploit",
            r"bypass",
            r"elevated",
            r"hacktool",
            r"kali",
            r"metasploit",
        ]

        # SEC_SUSPICIOUS_PATH 용 경로 패턴
        self.suspicious_path_patterns = [
            r"\\users\\public\\",
            r"\\users\\.+\\downloads\\",
            r"\\users\\.+\\appdata\\local\\temp\\",
            r"\\users\\.+\\appdata\\roaming\\",
            r"\\programdata\\",
            r"\\windows\\temp\\",
        ]

    # ========= 공통 유틸 =========

    def _parse_ts(self, value):
        if value is None or pd.isna(value) or value == "":
            return None
        try:
            return pd.to_datetime(value)
        except Exception:
            return None

    def get_recency_tag(self, ts):
        """TIME_* 태그는 항상 1개만 선택"""
        if ts is None:
            return None
        if ts >= self.one_day_ago:
            return "TIME_RECENT"
        elif ts >= self.one_week_ago:
            return "TIME_WEEK"
        elif ts >= self.one_month_ago:
            return "TIME_MONTH"
        else:
            return "TIME_OLD"

    def get_primary_timestamp(self, row, kind: str):
        """kind 별 대표 타임스탬프 1개 선택"""
        if kind == "MFT_ENTRY":
            for col in [
                "LastModified0x10",
                "Created0x10",
                "LastAccess0x10",
                "LastRecordChange0x10",
            ]:
                if col in row.index:
                    ts = self._parse_ts(row[col])
                    if ts is not None:
                        return ts

        elif kind == "MFT_FILE_LISTING":
            for col in ["LastModified0x10", "Created0x10"]:
                if col in row.index:
                    ts = self._parse_ts(row[col])
                    if ts is not None:
                        return ts

        elif kind == "MFT_DUMP_RESIDENT":
            for col in [
                "TargetModified",
                "TargetCreated",
                "SourceModified",
                "SourceCreated",
                "SourceAccessed",
            ]:
                if col in row.index:
                    ts = self._parse_ts(row[col])
                    if ts is not None:
                        return ts

        return None

    def build_description(self, row, fields):
        """필요 컬럼만 Key : Value | ... 형태로 연결"""
        parts = []
        for col in fields:
            if col in row.index:
                val = row[col]
                if pd.notna(val) and str(val) != "":
                    parts.append(f"{col} : {val}")
        return " | ".join(parts)

    def get_extension(self, row):
        ext = None
        if "Extension" in row.index and pd.notna(row["Extension"]):
            ext = str(row["Extension"]).lower().strip()
        elif "FileName" in row.index and pd.notna(row["FileName"]):
            name = str(row["FileName"])
            m = re.search(r"\.([^.]+)$", name)
            if m:
                ext = m.group(1).lower()
        return ext

    def has_suspicious_name(self, names):
        if not names:
            return False
        s = " ".join([str(n).lower() for n in names if n is not None])
        if not s:
            return False
        for p in self.suspicious_name_patterns:
            if re.search(p, s):
                return True
        return False

    def get_path(self, row, kind: str):
        """AREA_/SEC_SUSPICIOUS_PATH 용 경로 문자열 하나"""
        if kind == "MFT_ENTRY":
            parent = str(row.get("ParentPath") or "").lower()
            fname = str(row.get("FileName") or "").lower()
            if parent and not parent.endswith("\\"):
                parent += "\\"
            return (parent + fname).strip()

        if kind == "MFT_FILE_LISTING":
            if "FullPath" in row.index and pd.notna(row["FullPath"]):
                return str(row["FullPath"]).lower()

        if kind == "MFT_DUMP_RESIDENT":
            for col in ["RelativePath", "LocalPath", "TargetIDAbsolutePath"]:
                if col in row.index and pd.notna(row[col]) and row[col] != "":
                    return str(row[col]).lower()

        for col in ["FullPath", "ParentPath"]:
            if col in row.index and pd.notna(row[col]) and row[col] != "":
                return str(row[col]).lower()

        return ""

    # ========= FORMAT_/SEC_/AREA_/STATE_ =========

    def get_format_tags(self, ext):
        tags = []
        if not ext:
            return tags

        if ext in ["doc", "docx", "pdf", "txt", "rtf", "odt"]:
            tags.append("FORMAT_DOCUMENT")
        elif ext in ["xls", "xlsx", "csv"]:
            tags.append("FORMAT_SPREADSHEET")
        elif ext in ["ppt", "pptx"]:
            tags.append("FORMAT_PRESENTATION")
        elif ext in ["jpg", "jpeg", "png", "gif", "bmp", "ico", "svg", "heic", "hif"]:
            tags.append("FORMAT_IMAGE")
        elif ext in ["mp4", "avi", "mkv", "mov", "wmv"]:
            tags.append("FORMAT_VIDEO")
        elif ext in ["mp3", "wav", "flac", "wma"]:
            tags.append("FORMAT_AUDIO")
        elif ext in ["zip", "rar", "7z", "tar", "gz"]:
            tags.append("FORMAT_ARCHIVE")
        elif ext in ["exe", "dll", "sys", "scr", "com"]:
            tags.append("FORMAT_EXECUTABLE")
        elif ext in ["ps1", "bat", "cmd", "vbs", "js", "py"]:
            tags.append("FORMAT_SCRIPT")
        elif ext in ["db", "sqlite", "accdb", "mdb"]:
            tags.append("FORMAT_DATABASE")
        elif ext in ["evtx", "log"]:
            tags.append("FORMAT_LOG")
        elif ext in ["ini", "xml", "json", "yaml", "yml", "conf", "cfg"]:
            tags.append("FORMAT_CONFIG")
        elif ext in ["dat", "hve", "reg"]:
            tags.append("FORMAT_REGISTRY")
        elif ext in ["pst", "ost", "msg", "eml"]:
            tags.append("FORMAT_EMAIL")
        elif ext in ["lnk", "url"]:
            tags.append("FORMAT_SHORTCUT")

        return tags

    def get_sec_tags(self, row, ext, path):
        tags = []

        # 실행/스크립트
        if ext in ["exe", "dll", "sys", "scr", "com"]:
            tags.append("SEC_EXECUTABLE")
        if ext in ["ps1", "bat", "cmd", "vbs", "js", "py"]:
            tags.append("SEC_SCRIPT")

        # 이중 확장자
        name_fields = []
        if "FileName" in row.index and pd.notna(row["FileName"]):
            name_fields.append(str(row["FileName"]).lower())

        for n in name_fields:
            if re.search(r"\.(pdf|docx|jpg)\.(exe|scr|com)$", n):
                tags.append("SEC_SUSPICIOUS_EXTENSION")
                break

        # 이름 패턴
        if self.has_suspicious_name(name_fields):
            tags.append("SEC_SUSPICIOUS_NAME")

        # 경로 패턴
        if path:
            for pat in self.suspicious_path_patterns:
                if re.search(pat, path):
                    tags.append("SEC_SUSPICIOUS_PATH")
                    break

        return tags

    def get_area_tags(self, path):
        tags = []
        if not path:
            return tags

        p = path

        if r"\windows\system32" in p or r"\windows\syswow64" in p:
            tags.append("AREA_SYSTEM32")
        if p.startswith(r"c:\windows"):
            tags.append("AREA_WINDOWS")
        if re.search(r"\\users\\[^\\]+\\desktop\\", p):
            tags.append("AREA_USER_DESKTOP")
        if re.search(r"\\users\\[^\\]+\\documents\\", p):
            tags.append("AREA_USER_DOCUMENTS")
        if re.search(r"\\users\\[^\\]+\\downloads\\", p):
            tags.append("AREA_USER_DOWNLOADS")
        if re.search(r"\\users\\[^\\]+\\appdata\\local\\", p):
            tags.append("AREA_APPDATA_LOCAL")
        if re.search(r"\\users\\[^\\]+\\appdata\\roaming\\", p):
            tags.append("AREA_APPDATA_ROAMING")
        if r"\program files" in p:
            tags.append("AREA_PROGRAMFILES")
        if r"\programdata" in p:
            tags.append("AREA_PROGRAMDATA")
        if r"\windows\temp" in p:
            tags.append("AREA_TEMP")
        if r"\recycle.bin" in p:
            tags.append("AREA_RECYCLE_BIN")
        if p.startswith(r"\\"):
            tags.append("AREA_NETWORK_SHARE")

        return tags

    def get_state_tags(self, row):
        tags = []

        # 삭제 여부 ($MFT)
        if "InUse" in row.index:
            in_use = row.get("InUse")
            if str(in_use).strip().lower() in ["false", "0", "no"]:
                tags.append("STATE_DELETED")

        # 속성 플래그
        attr_text = ""
        for c in ["FileAttributes", "SiFlags"]:
            if c in row.index and pd.notna(row[c]):
                attr_text += " " + str(row[c]).lower()

        if "hidden" in attr_text:
            tags.append("STATE_HIDDEN")
        if "system" in attr_text:
            tags.append("STATE_SYSTEM")
        if "readonly" in attr_text:
            tags.append("STATE_READONLY")
        if "compressed" in attr_text:
            tags.append("STATE_COMPRESSED")
        if "encrypted" in attr_text:
            tags.append("STATE_ENCRYPTED")

        return tags

    def normalize_tags(self, tags):
        """중복 제거 + TIME_* 하나만 유지"""
        tags = list(dict.fromkeys(tags))
        time_tags = [
            t
            for t in tags
            if t in ["TIME_RECENT", "TIME_WEEK", "TIME_MONTH", "TIME_OLD"]
        ]
        if len(time_tags) > 1:
            priority = ["TIME_RECENT", "TIME_WEEK", "TIME_MONTH", "TIME_OLD"]
            chosen = None
            for p in priority:
                if p in time_tags:
                    chosen = p
                    break
            tags = [t for t in tags if t not in time_tags]
            if chosen:
                tags.append(chosen)
        return tags

    # ========= 스키마 기반 kind 감지 =========

    def detect_kind(self, df: pd.DataFrame, filename: str) -> str:
        """
        컬럼 구조를 보고 MFT 타입($MFT / $Boot / $FileListing / DumpResident)을 판별.
        파일명은 보조 정도로만 사용.
        """
        cols = set(df.columns)
        fn = filename.lower()

        if {"EntryNumber", "ParentPath", "FileName"}.issubset(cols):
            return "MFT_ENTRY"

        if {"EntryPoint", "BytesPerSector", "TotalSectors"}.issubset(cols):
            return "MFT_BOOT"

        if {"FullPath", "IsDirectory", "FileSize"}.issubset(cols):
            return "MFT_FILE_LISTING"

        if {"SourceCreated", "TargetCreated", "RelativePath"}.issubset(cols):
            return "MFT_DUMP_RESIDENT"

        # 파일명 기반 fallback
        if "$mft_dumpresidentfiles" in fn:
            return "MFT_DUMP_RESIDENT"
        if "$filelisting" in fn:
            return "MFT_FILE_LISTING"
        if "$boot" in fn:
            return "MFT_BOOT"
        if "$mft" in fn:
            return "MFT_ENTRY"

        return "MFT_UNKNOWN"

    # ========= 태깅 로직 =========

    def tag_mft_entry_like(self, row, kind: str):
        tags = ["ARTIFACT_MFT"]

        ext = self.get_extension(row)
        path = self.get_path(row, kind)
        ts = self.get_primary_timestamp(row, kind)
        recency = self.get_recency_tag(ts)
        if recency:
            tags.append(recency)

        tags.extend(self.get_format_tags(ext))
        tags.extend(self.get_sec_tags(row, ext, path))
        tags.extend(self.get_area_tags(path))
        tags.extend(self.get_state_tags(row))

        tags = self.normalize_tags(tags)
        return " | ".join(tags), ts

    def tag_boot(self, row):
        tags = ["ARTIFACT_MFT"]
        tags.extend(self.get_state_tags(row))
        tags = self.normalize_tags(tags)
        return " | ".join(tags), None

    def tag_default(self, row, kind: str):
        tags = ["ARTIFACT_MFT"]
        ts = self.get_primary_timestamp(row, kind)
        recency = self.get_recency_tag(ts)
        if recency:
            tags.append(recency)
        tags.extend(self.get_state_tags(row))
        tags = self.normalize_tags(tags)
        return " | ".join(tags), ts

    # ========= 메인 처리 =========

    def process_csv(self, csv_path, output_root):
        """
        MFTECmd CSV 하나를 읽어서
        Type / LastWriteTimestamp / description / Tags JSONL로 출력
        output_root 아래에 바로 저장
        """
        csv_path = Path(csv_path)
        filename = csv_path.name

        df = pd.read_csv(csv_path)

        # kind 결정 (스키마 기준)
        kind = self.detect_kind(df, filename)
        base_type = kind if kind != "MFT_UNKNOWN" else "MFT_UNKNOWN"

        out_rows = []

        for _, row in df.iterrows():
            if kind == "MFT_ENTRY":
                desc_fields = [
                    "ParentPath",
                    "FileName",
                    "Extension",
                    "FileSize",
                    "InUse",
                    "IsDirectory",
                    "HasAds",
                    "IsAds",
                    "ReparseTarget",
                    "SiFlags",
                    "Created0x10",
                    "LastModified0x10",
                    "LastRecordChange0x10",
                    "LastAccess0x10",
                ]
            elif kind == "MFT_FILE_LISTING":
                desc_fields = [
                    "FullPath",
                    "Extension",
                    "IsDirectory",
                    "FileSize",
                    "Created0x10",
                    "LastModified0x10",
                ]
            elif kind == "MFT_DUMP_RESIDENT":
                desc_fields = [
                    "RelativePath",
                    "LocalPath",
                    "NetworkPath",
                    "CommonPath",
                    "WorkingDirectory",
                    "Arguments",
                    "FileSize",
                    "FileAttributes",
                    "DriveType",
                    "TargetIDAbsolutePath",
                    "SourceCreated",
                    "SourceModified",
                    "SourceAccessed",
                    "TargetCreated",
                    "TargetModified",
                    "TargetAccessed",
                    "TrackerCreatedOn",
                ]
            elif kind == "MFT_BOOT":
                desc_fields = [
                    "BytesPerSector",
                    "SectorsPerCluster",
                    "ClusterSize",
                    "TotalSectors",
                    "MftEntrySize",
                    "IndexEntrySize",
                    "VolumeSerialNumber",
                ]
            else:
                desc_fields = list(df.columns[:10])

            description = self.build_description(row, desc_fields)

            if kind == "MFT_BOOT":
                tags_str, ts = self.tag_boot(row)
            elif kind in ["MFT_ENTRY", "MFT_FILE_LISTING", "MFT_DUMP_RESIDENT"]:
                tags_str, ts = self.tag_mft_entry_like(row, kind)
            else:
                tags_str, ts = self.tag_default(row, kind)

            out_rows.append(
                {
                    "Type": base_type,
                    "LastWriteTimestamp": ts,
                    "description": description,
                    "Tags": tags_str,
                }
            )

        out_df = pd.DataFrame(out_rows)

        # 🔥 여기서 바로 csvtag_output 으로 저장
        output_root = Path(output_root)
        output_root.mkdir(parents=True, exist_ok=True)
        jsonl_out = output_root / f"{csv_path.stem}_tagged.jsonl"

        out_df.to_json(jsonl_out, orient="records", lines=True, force_ascii=False)

        return str(jsonl_out), len(out_rows)


# ========= 실행부 =========

if __name__ == "__main__":
    from pathlib import Path

    tagger = MFTTagger()

    base_dir = Path(__file__).resolve().parent  # MFTCmd.py 있는 폴더

    # 입력: 현재 폴더 기준으로 검색 (지금 구조가 이미 잘 동작하고 있으면 이 줄은 건드릴 필요 없음)
    input_root = base_dir  # 또는 네가 기존에 쓰던 값 그대로 유지해도 됨

    # 출력: MFTCmd.py 있는 폴더 바로 아래의 csvtag_output
    output_root = base_dir / "csvtag_output"
    output_root.mkdir(parents=True, exist_ok=True)

    if not input_root.exists():
        print(f"폴더를 찾을 수 없지혁..: {input_root}")
        raise SystemExit(1)

    csv_files = [
        p
        for p in input_root.rglob("*MFTECmd_*.csv")
        if "_tagged" not in p.name
    ]

    if not csv_files:
        print("처리할 MFTECmd CSV 파일이 없습니다.")
    else:
        print(f"총 {len(csv_files)}개의 MFTECmd CSV 파일을 찾았습니다.\n")

        for i, csv_path in enumerate(csv_files, 1):
            try:
                print(f"[{i}/{len(csv_files)}] 처리 중: {csv_path}")
                jsonl_out, row_count = tagger.process_csv(csv_path, output_root)
                print(f"  JSONL 완료: {jsonl_out} ({row_count:,}개 행)\n")
            except Exception as e:
                print(f"  오류 발생: {csv_path} → {e}\n")

        print("=" * 50)
        print("모든 파일 처리 완료!")