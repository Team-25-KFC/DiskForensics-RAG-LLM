import pandas as pd
import os
import re
from datetime import datetime, timedelta
from pathlib import Path
import platform

# Windows 전용 모듈
try:
    import win32api
except ImportError:
    pass

class LogFileTagger:
    """NTFS LogFile CSV 파일 태깅 클래스"""
    
    def __init__(self, search_root=None, drive_path=None):
        
        # KAPE Output 폴더가 발견된 경우 외장 드라이브에 'tagged' 폴더를 사용
        if drive_path:
            self.output_dir = Path(drive_path) / "tagged"
        else:
            # 발견되지 않은 경우 (현재 폴더 검색 모드 시) 현재 폴더에 'tagged' 폴더를 사용
            self.output_dir = Path("tagged")
            
        self.output_dir.mkdir(exist_ok=True)
        
        # 검색 루트 설정 (None이면 현재 폴더)
        self.search_root = search_root
        
        self.columns_to_drop = ['Redo', 'Target VCN', 'Cluster Index']
        
        self.suspicious_keywords = [
            'crack', 'keygen', 'patch', 'activator',
            'mimikatz', 'psexec', 'procdump', 'lazagne', 'bloodhound', 'sharphound',
            'rubeus', 'certutil', 'bitsadmin', 'responder', 'empire', 'covenant',
            'cobalt', 'meterpreter', 'metasploit', 'nmap', 'masscan',
            'backdoor', 'payload', 'trojan', 'ransomware', 'malware', 'virus',
            'rootkit', 'exploit', 'cryptolocker', 'wannacry', 'emotet', 'trickbot',
            'bypass', 'hidden', 'invoke-', 'downloadstring', 'iex', 'encoded',
            '-enc', '-nop', '-w hidden',
            'hack', 'pwn', 'shell', 'reverse', 'bind'
        ]
        
        self.time_columns_priority = [
            ('Access Time', 'ACCESSED', 1),
            ('Modified Time', 'MODIFIED', 2),
            ('MFT_Modified Time', 'MODIFIED', 2),
            ('Create Time', 'CREATED', 3),
            ('EventTime(UTC+9)', 'EVENT', 4)
        ]
        
        self.time_spoofing_threshold_sec = 60
    
    def extract_parse_time_from_filename(self, filename):
        match = re.search(r'(\d{8,14})', str(filename))
        if match:
            time_str = match.group(1)
            try:
                if len(time_str) == 14:
                    parse_time = datetime.strptime(time_str, '%Y%m%d%H%M%S')
                elif len(time_str) == 8:
                    parse_time = datetime.strptime(time_str, '%Y%m%d')
                else:
                    return datetime.now()
                return parse_time
            except:
                pass
        
        return datetime.now()
        
    def get_latest_timestamp(self, row):
        timestamp_data = []
        
        for col, tag_type, priority in self.time_columns_priority:
            if col in row.index and pd.notna(row[col]):
                try:
                    ts = pd.to_datetime(row[col], errors='coerce')
                    if ts is not pd.NaT and ts.year > 1980:
                        timestamp_data.append((ts, tag_type, priority))
                except:
                    pass
        
        if not timestamp_data:
            for col in row.index:
                if 'time' in col.lower() and pd.notna(row[col]):
                    try:
                        ts = pd.to_datetime(row[col], errors='coerce')
                        if ts is not pd.NaT and ts.year > 1980:
                            timestamp_data.append((ts, 'UNKNOWN', 5))
                    except:
                        pass
        
        if timestamp_data:
            latest = max(timestamp_data, key=lambda x: (x[0], -x[2]))
            return latest[0], latest[1]
        
        return None, None
    
    def get_time_range_tag(self, timestamp, reference_time):
        if pd.isna(timestamp):
            return None
        
        one_day_ago = reference_time - timedelta(days=1, seconds=1)
        one_week_ago = reference_time - timedelta(days=7, seconds=1)
        one_month_ago = reference_time - timedelta(days=30, seconds=1)
        
        if timestamp >= one_day_ago:
            return 'TIME_RECENT'
        elif timestamp >= one_week_ago:
            return 'TIME_WEEK'
        elif timestamp >= one_month_ago:
            return 'TIME_MONTH'
        else:
            return 'TIME_OLD'
    
    def get_artifact_tags(self, row):
        tags = []
        
        file_dir = str(row.get('File/Directory Name', row.get('File/Directory', ''))).lower()
        
        # 레지스트리 관련 특정 파일만 매칭
        registry_files = ['ntuser.dat', 'usrclass.dat', 'software', 'system', 'sam', 'security', 'default']
        if any(x in file_dir for x in registry_files) or \
           file_dir.endswith(('.hve', '.reg')):
            tags.append('ARTIFACT_REGISTRY')
        
        if 'usrclass.dat' in file_dir:
            if 'ARTIFACT_REGISTRY' not in tags:
                tags.append('ARTIFACT_REGISTRY')
            tags.append('ARTIFACT_SHELLBAG')
        
        elif any(x in file_dir for x in ['$mft', '$logfile', '$boot', '$volume', '$bitmap', '$secure', '$quota', '$objid']):
            tags.append('ARTIFACT_MFT')
        
        elif '$usnjrnl' in file_dir or '$j' in file_dir:
            tags.append('ARTIFACT_USN_JOURNAL')
        
        elif file_dir.endswith('.evtx'):
            tags.append('ARTIFACT_EVENT_LOG')
        
        elif file_dir.endswith('.pf'):
            tags.append('ARTIFACT_PREFETCH')
        
        elif file_dir.endswith('.lnk'):
            tags.append('ARTIFACT_LNK')
        
        elif 'automaticdestinations' in file_dir or 'customdestinations' in file_dir or file_dir.endswith('-ms'):
            tags.append('ARTIFACT_JUMPLIST')
        
        elif 'amcache' in file_dir or 'recentfilecache' in file_dir:
            tags.append('ARTIFACT_AMCACHE')
        
        elif 'srudb.dat' in file_dir:
            tags.append('ARTIFACT_SRUM')
        
        elif '$recycle.bin' in file_dir or file_dir.startswith('$i') or file_dir.startswith('$r'):
            tags.append('ARTIFACT_RECYCLE_BIN')
        
        elif any(x in file_dir for x in ['chrome', 'edge', 'firefox', 'internet explorer', 'browser']):
            if 'history' in file_dir or 'visited' in file_dir:
                tags.append('ARTIFACT_BROWSER_HISTORY')
            elif 'cookie' in file_dir:
                tags.append('ARTIFACT_BROWSER_COOKIE')
            elif 'cache' in file_dir:
                tags.append('ARTIFACT_BROWSER_CACHE')
            else:
                tags.append('ARTIFACT_BROWSER')
        
        elif any(x in file_dir for x in ['.pst', '.ost', '.msg', '.eml']):
            tags.append('ARTIFACT_EMAIL')
        
        elif file_dir.endswith(('.db', '.sqlite', '.accdb', '.mdb')):
            tags.append('ARTIFACT_DB')
        
        elif 'thumbs.db' in file_dir or 'thumbcache' in file_dir:
            tags.append('ARTIFACT_THUMBNAIL')
        
        # 마지막에 태그가 없으면 일반 파일로 분류
        if not tags:
            tags.append('ARTIFACT_FILE')
        
        return tags
    
    def get_event_tags(self, row):
        tags = []
        event = str(row.get('Event', '')).lower()
        detail = str(row.get('Detail', '')).lower()
        
        if 'creation' in event or 'file creation' in event or 'initialize file record segment' in event:
            tags.append('EVENT_CREATE')
        elif 'deletion' in event or 'file deletion' in event or 'deallocate' in detail or 'remove file name' in detail:
            tags.append('EVENT_DELETE')
        elif 'renaming' in event:
            tags.append('EVENT_RENAME')
        elif any(x in event for x in ['modifi', 'updating', 'writing']) or \
             'update resident value' in event or 'update mapping pairs' in event:
            tags.append('EVENT_MODIFY')
        elif 'time reve' in event:
            tags.append('EVENT_TIMESTAMP_CHANGE')
        
        if 'access' in event or 'read' in event:
            tags.append('EVENT_ACCESS')
        
        if 'move' in detail:
            tags.append('EVENT_MOVE')
        
        return tags
    
    def get_area_tags(self, row):
        tags = []
        path_info = str(row.get('Full Path', row.get('File/DirectoryFull Path', ''))).lower()
        
        if not path_info or len(path_info) < 5:
            path_info = str(row.get('File/Directory Name', '')).lower() + str(row.get('Detail', '')).lower()
        
        if '\\system32' in path_info or '\\syswow64' in path_info:
            tags.append('AREA_SYSTEM32')
        elif path_info.startswith('c:\\windows') and 'AREA_SYSTEM32' not in tags:
            tags.append('AREA_WINDOWS')
        
        if '\\users\\' in path_info:
            if '\\desktop' in path_info:
                tags.append('AREA_USER_DESKTOP')
            elif '\\documents' in path_info:
                tags.append('AREA_USER_DOCUMENTS')
            elif '\\downloads' in path_info:
                tags.append('AREA_USER_DOWNLOADS')
            elif '\\recent' in path_info:
                tags.append('AREA_USER_RECENT')
            elif '\\appdata\\local' in path_info:
                if '\\appdata\\locallow' in path_info:
                    tags.append('AREA_APPDATA_LOCALLOW')
                else:
                    tags.append('AREA_APPDATA_LOCAL')
            elif '\\appdata\\roaming' in path_info:
                tags.append('AREA_APPDATA_ROAMING')
            
            if not any(t.startswith('AREA_USER_') or t.startswith('AREA_APPDATA_') for t in tags):
                tags.append('AREA_USER_PROFILE')
        
        if '\\program files' in path_info:
            tags.append('AREA_PROGRAMFILES')
        elif '\\programdata' in path_info:
            tags.append('AREA_PROGRAMDATA')
        
        if '\\temp' in path_info or '\\tmp' in path_info:
            tags.append('AREA_TEMP')
        
        if '\\startup' in path_info:
            tags.append('AREA_STARTUP')
        if '\\prefetch' in path_info:
            tags.append('AREA_PREFETCH')
        if '$recycle.bin' in path_info:
            tags.append('AREA_RECYCLE_BIN')
        if 'system volume information' in path_info:
            tags.append('AREA_VSS')
        if path_info.startswith('\\\\'):
            tags.append('AREA_NETWORK_SHARE')
        if re.match(r'^[d-z]:\\', path_info):
            tags.append('AREA_EXTERNAL_DRIVE')
        
        return tags
    
    def get_sec_tags(self, row):
        tags = []
        file_dir = str(row.get('File/Directory Name', row.get('File/Directory', ''))).lower()
        event = str(row.get('Event', '')).lower()
        detail = str(row.get('Detail', '')).lower()
        path_info = str(row.get('Full Path', row.get('File/DirectoryFull Path', ''))).lower()
        
        if 'time reve' in event or 'time reve' in detail:
            tags.append('SEC_TIME_SPOOFING')
        
        create_time = row.get('Create Time')
        modified_time = row.get('Modified Time')
        
        if create_time and modified_time:
            try:
                ct = pd.to_datetime(create_time, errors='coerce')
                mt = pd.to_datetime(modified_time, errors='coerce')
                
                if ct is not pd.NaT and mt is not pd.NaT:
                    if ct.year > 1980 and mt.year > 1980:
                        if ct > mt:
                            time_diff = (ct - mt).total_seconds()
                            if time_diff > self.time_spoofing_threshold_sec:
                                tags.append('SEC_TIME_SPOOFING')
            except:
                pass
        
        if file_dir.endswith(('.exe', '.dll', '.sys', '.scr', '.com', '.cpl')):
            tags.append('SEC_EXECUTABLE')
            if any(x in path_info for x in ['\\temp', '\\downloads', '\\appdata\\local\\temp']):
                tags.append('SEC_SUSPICIOUS_PATH')
        
        if file_dir.endswith(('.ps1', '.bat', '.vbs', '.js', '.cmd', '.wsf', '.hta')):
            tags.append('SEC_SCRIPT')
        
        if any(keyword in file_dir for keyword in self.suspicious_keywords):
            tags.append('SEC_SUSPICIOUS_NAME')
        
        if re.search(r'\.(pdf|jpg|png|doc|xls)\.(exe|scr|com|bat|vbs)$', file_dir):
            tags.append('SEC_SUSPICIOUS_EXTENSION')
        
        if any(x in detail for x in ['\\software\\microsoft\\windows\\currentversion\\run', '\\winlogon', '\\services']):
            tags.append('SEC_PERSISTENCE_REGISTRY')
        
        if '\\startup' in path_info or 'run' in path_info:
            tags.append('SEC_PERSISTENCE_STARTUP')
        
        if 'network persistent state' in file_dir:
            tags.append('SEC_PERSISTENCE_NETWORK')
        
        if '\\tasks\\' in path_info or file_dir.endswith('.job'):
            tags.append('SEC_PERSISTENCE_TASK')
        
        return tags
    
    def get_format_tags(self, row):
        tags = []
        file_dir = str(row.get('File/Directory Name', row.get('File/Directory', ''))).lower()
        
        if file_dir.endswith(('.doc', '.docx', '.pdf', '.txt', '.rtf', '.odt')):
            tags.append('FORMAT_DOCUMENT')
        elif file_dir.endswith(('.xls', '.xlsx', '.csv')):
            tags.append('FORMAT_SPREADSHEET')
        elif file_dir.endswith(('.ppt', '.pptx')):
            tags.append('FORMAT_PRESENTATION')
        elif file_dir.endswith(('.jpg', '.jpeg', '.png', '.gif', '.bmp', '.ico', '.svg', '.webp')):
            tags.append('FORMAT_IMAGE')
        elif file_dir.endswith(('.mp4', '.avi', '.mkv', '.mov', '.wmv', '.flv')):
            tags.append('FORMAT_VIDEO')
        elif file_dir.endswith(('.mp3', '.wav', '.flac', '.wma', '.aac')):
            tags.append('FORMAT_AUDIO')
        elif file_dir.endswith(('.zip', '.rar', '.7z', '.tar', '.gz', '.bz2')):
            tags.append('FORMAT_ARCHIVE')
        elif file_dir.endswith(('.exe', '.dll', '.sys', '.com', '.scr', '.cpl')):
            tags.append('FORMAT_EXECUTABLE')
        elif file_dir.endswith(('.ps1', '.bat', '.vbs', '.js', '.py', '.cmd', '.sh', '.hta')):
            tags.append('FORMAT_SCRIPT')
        elif file_dir.endswith(('.db', '.sqlite', '.accdb', '.mdb')):
            tags.append('FORMAT_DATABASE')
        elif file_dir.endswith('.evtx') or 'log' in file_dir:
            tags.append('FORMAT_LOG')
        elif file_dir.endswith(('.ini', '.xml', '.json', '.yaml', '.yml', '.conf', '.cfg', '.tmp')):
            tags.append('FORMAT_CONFIG')
        elif file_dir.endswith(('.hve', '.reg')):
            tags.append('FORMAT_REGISTRY')
        elif file_dir.endswith(('.pst', '.ost', '.msg', '.eml')):
            tags.append('FORMAT_EMAIL')
        elif file_dir.endswith(('.lnk', '.url')):
            tags.append('FORMAT_SHORTCUT')
        
        return tags
    
    def get_act_tags(self, row):
        tags = []
        file_dir = str(row.get('File/Directory Name', row.get('File/Directory', ''))).lower()
        detail = str(row.get('Detail', '')).lower()
        path_info = str(row.get('Full Path', row.get('File/DirectoryFull Path', ''))).lower()
        
        if '\\downloads' in path_info:
            tags.append('ACT_DOWNLOAD')
        
        if '\\program files' in path_info or 'install' in detail or 'setup' in file_dir:
            if 'uninstall' in detail:
                tags.append('ACT_UNINSTALL')
            else:
                tags.append('ACT_INSTALL')
        
        if any(x in path_info for x in ['\\cache', '\\history', '\\cookies']):
            tags.append('ACT_BROWSING')
        
        if path_info.startswith('\\\\') or 'network' in detail:
            tags.append('ACT_NETWORK_ACCESS')
        
        if 'prefetch' in path_info or file_dir.endswith('.pf'):
            tags.append('ACT_EXECUTE')
        
        return tags
    
    def generate_tags(self, row, reference_time):
        tags = []
        
        tags.extend(self.get_artifact_tags(row))
        tags.extend(self.get_event_tags(row))
        tags.extend(self.get_area_tags(row))
        tags.extend(self.get_sec_tags(row))
        tags.extend(self.get_format_tags(row))
        tags.extend(self.get_act_tags(row))
        
        latest_ts, ts_type = self.get_latest_timestamp(row)
        if latest_ts:
            time_range_tag = self.get_time_range_tag(latest_ts, reference_time)
            if time_range_tag:
                tags.append(time_range_tag)
            
            if ts_type == 'CREATED':
                tags.append('TIME_CREATED')
            elif ts_type == 'MODIFIED':
                tags.append('TIME_MODIFIED')
            elif ts_type == 'ACCESSED':
                tags.append('TIME_ACCESSED')
        
        tags = sorted(list(set(tags)))
        
        return " | ".join(tags) if tags else "NO_TAG"
    
    def create_description(self, row, exclude_cols=['Type', 'LastWriteTimestamp', 'Tags']):
        desc_parts = []
        
        for col, value in row.items():
            if col in exclude_cols or col in self.columns_to_drop:
                continue
            
            if pd.isna(value) or value == '':
                continue
            
            str_value = str(value).strip()
            if str_value:
                desc_parts.append(f"{col}: {str_value}")
        
        return " | ".join(desc_parts)
    
    def process_csv(self, csv_path, folder_path=""):
        """CSV 파일 처리"""
        filename = Path(csv_path).name
        
        reference_time = self.extract_parse_time_from_filename(filename)
        print(f"  ℹ️  파싱 기준 시간: {reference_time.strftime('%Y-%m-%d %H:%M:%S')}")
        
        df = None
        encodings = ['utf-8-sig', 'utf-8', 'cp949', 'euc-kr', 'latin1', 'iso-8859-1']
        
        for encoding in encodings:
            try:
                df = pd.read_csv(csv_path, encoding=encoding)
                print(f"  ℹ️  인코딩: {encoding}")
                break
            except (UnicodeDecodeError, pd.errors.ParserError):
                continue
        
        if df is None:
            raise ValueError(f"인코딩을 감지할 수 없습니다.")
        
        if df.empty or len(df) == 0:
            raise ValueError(f"빈 파일입니다.")
        
        result_rows = []
        
        for idx, row in df.iterrows():
            artifact_type = "$LogFile"
            
            latest_time, _ = self.get_latest_timestamp(row)
            last_write_timestamp = latest_time.strftime('%Y-%m-%d %H:%M:%S') if latest_time else ''
            
            tags = self.generate_tags(row, reference_time)
            description = self.create_description(row)
            
            result_rows.append({
                'Type': artifact_type,
                'LastWriteTimestamp': last_write_timestamp,
                'Description': description,
                'Tags': tags
            })
        
        result_df = pd.DataFrame(result_rows)
        
        # 출력 파일명에 폴더 경로 포함
        if folder_path and folder_path != ".":
            output_filename = f"{folder_path}_tagged_{filename}"
        else:
            output_filename = filename.replace('.csv', '_tagged.csv')
        
        output_path = self.output_dir / output_filename
        result_df.to_csv(output_path, index=False, encoding='utf-8-sig')
        
        print(f"  ℹ️  원본 컬럼: {len(df.columns)}개 → 정제 후: 4개")
        
        return str(output_path), len(result_df)
    
    def find_csv_files(self):
        """검색 루트에서 LogFile CSV 파일 찾기"""
        csv_files = []
        
        if self.search_root:
            # KAPE Output 하위 재귀 검색
            for root, _, files in os.walk(self.search_root):
                for file in files:
                    if 'LogFile' in file and file.endswith('.csv') and '_tagged' not in file:
                        full_path = os.path.join(root, file)
                        # 상대 경로 추출
                        relative_path = os.path.relpath(root, self.search_root)
                        folder_prefix = relative_path.replace(os.sep, '_').replace(' ', '_')
                        csv_files.append((full_path, folder_prefix))
        else:
            # 현재 폴더만 검색 (기존 방식)
            import glob
            for file in glob.glob("*LogFile*.csv"):
                if '_tagged' not in file:
                    csv_files.append((file, ""))
        
        return csv_files


# --- 사용 예시 ---
if __name__ == "__main__":
    
    # Windows에서 KAPE Output 자동 탐색
    search_root = None
    drive_path = None
    
    if platform.system() == "Windows":
        try:
            if 'win32api' in globals():
                drives = win32api.GetLogicalDriveStrings()
                drives = drives.split('\x00')[:-1]
                
                for drive in drives:
                    if drive.upper() in ["A:\\", "B:\\", "C:\\"]:
                        continue
                    
                    try:
                        for item in os.listdir(drive):
                            # ⭐ 수정: fullmatch 사용으로 정확한 매칭
                            if re.fullmatch(r"kape\s*output", item, re.IGNORECASE):
                                search_root = os.path.join(drive, item)
                                drive_path = drive
                                print(f"✅ KAPE Output 폴더 발견: {search_root}")
                                break
                    except:
                        pass
                    
                    if search_root:
                        break
        except ImportError:
            pass
    
    # 태거 초기화
    tagger = LogFileTagger(search_root=search_root, drive_path=drive_path)
    
    # CSV 파일 찾기
    csv_files = tagger.find_csv_files()
    
    if not csv_files:
        print("처리할 LogFile CSV 파일이 없습니다.")
    else:
        print(f"총 {len(csv_files)}개의 LogFile CSV 파일을 찾았습니다.")
        print(f"출력 폴더: {tagger.output_dir.absolute()}\n")
        
        for i, (csv_file, folder_prefix) in enumerate(csv_files, 1):
            try:
                print(f"[{i}/{len(csv_files)}] 처리 중: {csv_file}")
                if folder_prefix and folder_prefix != ".":
                    print(f"  ℹ️  폴더 경로: {folder_prefix}")
                output_file, row_count = tagger.process_csv(csv_file, folder_prefix)
                print(f"  ✔ 완료: {output_file} ({row_count:,}개 행)\n")
            except Exception as e:
                print(f"  ✗ 오류 발생: {str(e)}\n")
        
        print("=" * 50)
        print(f"모든 파일 처리 완료!")
        print(f"결과 파일 위치: {tagger.output_dir.absolute()}")