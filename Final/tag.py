#!/usr/bin/env python3
# -*- coding: utf-8 -*-
import csv
import re
import os
from pathlib import Path
from datetime import datetime, timedelta

csv.field_size_limit(10 * 1024 * 1024)

class ExtendedArtifactTagger:
    def __init__(self):
        # 기본 태거 패턴들
        self.format_map = {
            'FORMAT_DOCUMENT': ['.doc', '.docx', '.pdf', '.txt', '.rtf', '.hwp', '.xls', '.xlsx', '.ppt', '.pptx'],
            'FORMAT_IMAGE': ['.jpg', '.jpeg', '.png', '.gif', '.bmp', '.ico', '.svg', '.webp'],
            'FORMAT_VIDEO': ['.mp4', '.avi', '.mkv', '.mov', '.wmv', '.flv', '.webm'],
            'FORMAT_AUDIO': ['.mp3', '.wav', '.flac', '.aac', '.ogg', '.wma', '.m4a'],
            'FORMAT_ARCHIVE': ['.zip', '.rar', '.7z', '.tar', '.gz', '.bz2', '.iso'],
            'FORMAT_EXECUTABLE': ['.exe', '.dll', '.sys', '.bat', '.cmd', '.msi', '.com', '.scr'],
            'FORMAT_SCRIPT': ['.ps1', '.vbs', '.js', '.py', '.sh', '.php', '.rb', '.pl'],
            'FORMAT_DATABASE': ['.db', '.sqlite', '.mdb', '.accdb', '.dbf'],
            'FORMAT_LOG': ['.log', '.evtx', '.evt', '.etl']
        }
        
        self.area_patterns = {
            'AREA_SYSTEM32': r'(?i)\\system32\\|\\syswow64\\',
            'AREA_USER_DESKTOP': r'(?i)\\desktop\\',
            'AREA_USER_DOCUMENTS': r'(?i)\\documents\\|\\my documents\\',
            'AREA_USER_DOWNLOADS': r'(?i)\\downloads\\',
            'AREA_APPDATA_LOCAL': r'(?i)\\appdata\\local\\',
            'AREA_APPDATA_ROAMING': r'(?i)\\appdata\\roaming\\',
            'AREA_PROGRAMFILES': r'(?i)\\program files\\|\\program files \(x86\)\\',
            'AREA_TEMP': r'(?i)\\temp\\|\\tmp\\',
            'AREA_RECYCLE_BIN': r'(?i)\\\$recycle\.bin\\|\\recycler\\',
            'AREA_VOLUME_SHADOW': r'(?i)\\system volume information\\|globalroot\\device\\harddiskvolumeshadowcopy'
        }
        
        self.security_patterns = {
            'SEC_SUSPICIOUS_NAME': r'(?i)(crack|keygen|patch|hack|payload|malware|trojan|virus|ransomware|backdoor|rootkit|mimikatz)',
            'SEC_PERSISTENCE_PATH': r'(?i)\\startup\\|\\run\\|\\runonce\\|\\userinit|\\winlogon',
            'SEC_ALTERNATE_DATA_STREAM': r'(?i):.*:\$data',  # ADS 패턴
            'SEC_HIDDEN_EXECUTABLE': r'(?i)^\.|\\\..*\.(exe|dll|sys)$'
        }

    # ==================== MFT 전용 태거 ====================
    def tag_mft_entry(self, row):
        """$MFT 엔트리 전용 태깅"""
        tags = ['ARTIFACT_MFT']
        
        # MFT 엔트리 번호 추출
        entry_num = row.get('entry', row.get('mft_entry', row.get('entry_number', '')))
        if entry_num:
            tags.append('MFT_HAS_ENTRY_NUMBER')
            # 시스템 파일 엔트리 (0-27은 특수 파일들)
            try:
                if int(str(entry_num).split('-')[0]) < 28:
                    tags.append('MFT_SYSTEM_ENTRY')
            except:
                pass
        
        # 파일 레퍼런스
        if row.get('parent_entry', row.get('parent_reference', '')):
            tags.append('MFT_HAS_PARENT_REF')
        
        # 시퀀스 번호 (파일 재사용 감지)
        sequence = row.get('sequence', row.get('sequence_number', ''))
        if sequence and str(sequence) != '0' and str(sequence) != '1':
            tags.append('MFT_REUSED_ENTRY')
        
        # 파일 속성 플래그
        attributes = str(row.get('attributes', row.get('flags', ''))).upper()
        if 'FILE_NAME' in attributes or '$FILE_NAME' in attributes:
            tags.append('MFT_HAS_FILENAME_ATTR')
        if 'DATA' in attributes or '$DATA' in attributes:
            tags.append('MFT_HAS_DATA_ATTR')
        if 'STANDARD_INFORMATION' in attributes or '$STANDARD_INFORMATION' in attributes:
            tags.append('MFT_HAS_SI_ATTR')
        if 'ATTRIBUTE_LIST' in attributes or '$ATTRIBUTE_LIST' in attributes:
            tags.append('MFT_HAS_ATTR_LIST')
        if 'INDEX_ROOT' in attributes or '$INDEX_ROOT' in attributes:
            tags.append('MFT_DIRECTORY')
        if 'BITMAP' in attributes or '$BITMAP' in attributes:
            tags.append('MFT_HAS_BITMAP')
        if 'REPARSE_POINT' in attributes or '$REPARSE_POINT' in attributes:
            tags.append('MFT_REPARSE_POINT')
        if 'EA' in attributes or '$EA' in attributes:
            tags.append('MFT_HAS_EA')
        if 'LOGGED_UTILITY_STREAM' in attributes or '$LOGGED_UTILITY_STREAM' in attributes:
            tags.append('MFT_HAS_LOG_STREAM')
        
        # 플래그 분석
        flags = str(row.get('flags', row.get('file_flags', ''))).upper()
        if 'IN_USE' in flags or 'ALLOCATED' in flags:
            tags.append('MFT_IN_USE')
        else:
            tags.append('MFT_DELETED')
        
        if 'DIRECTORY' in flags or 'DIR' in flags:
            tags.append('MFT_IS_DIRECTORY')
        else:
            tags.append('MFT_IS_FILE')
        
        # 레지던트/논레지던트
        resident = str(row.get('resident', row.get('is_resident', ''))).upper()
        if resident in ['TRUE', '1', 'YES', 'RESIDENT']:
            tags.append('MFT_RESIDENT')
        elif resident in ['FALSE', '0', 'NO', 'NON-RESIDENT', 'NONRESIDENT']:
            tags.append('MFT_NONRESIDENT')
        
        # Alternate Data Stream (ADS)
        filename = row.get('filename', row.get('name', ''))
        if ':' in str(filename) and not filename.endswith(':'):
            tags.append('MFT_HAS_ADS')
            if re.search(r':.*:\$DATA', str(filename), re.IGNORECASE):
                tags.append('SEC_ALTERNATE_DATA_STREAM')
        
        # 파일 크기 분석
        file_size = row.get('size', row.get('file_size', row.get('data_size', '')))
        allocated_size = row.get('allocated_size', row.get('alloc_size', ''))
        
        try:
            size_val = int(str(file_size).replace(',', ''))
            if size_val == 0:
                tags.append('MFT_ZERO_SIZE')
            elif size_val < 1024:
                tags.append('MFT_VERY_SMALL')
            elif size_val > 1024*1024*1024:  # > 1GB
                tags.append('MFT_LARGE_FILE')
            
            # 슬랙 공간 존재 여부
            if allocated_size:
                alloc_val = int(str(allocated_size).replace(',', ''))
                if alloc_val > size_val:
                    tags.append('MFT_HAS_SLACK')
        except:
            pass
        
        # 타임스탬프 불일치 (MACB time stomping 감지)
        si_modified = row.get('si_modified', row.get('si_mtime', ''))
        fn_modified = row.get('fn_modified', row.get('fn_mtime', ''))
        
        if si_modified and fn_modified:
            try:
                si_time = self._parse_time(si_modified)
                fn_time = self._parse_time(fn_modified)
                if si_time and fn_time:
                    time_diff = abs((si_time - fn_time).total_seconds())
                    if time_diff > 1:  # 1초 이상 차이
                        tags.append('MFT_TIMESTAMP_MISMATCH')
                        if si_time < fn_time:
                            tags.append('MFT_POSSIBLE_TIMESTOMP')
            except:
                pass
        
        # 의심스러운 생성 시간 (1970년 이전, 미래)
        created = row.get('created', row.get('created_time', row.get('si_created', '')))
        if created:
            try:
                created_time = self._parse_time(created)
                if created_time:
                    if created_time.year < 1980:
                        tags.append('MFT_SUSPICIOUS_CREATED_TIME')
                    elif created_time > datetime.now() + timedelta(days=1):
                        tags.append('MFT_FUTURE_TIMESTAMP')
            except:
                pass
        
        return tags

    # ==================== USN 저널 전용 태거 ====================
    def tag_usn_journal(self, row):
        """USN 저널 전용 태깅"""
        tags = ['ARTIFACT_USN_JOURNAL']
        
        # USN (Update Sequence Number)
        usn = row.get('usn', row.get('update_sequence_number', ''))
        if usn:
            tags.append('USN_HAS_USN')
        
        # 파일 레퍼런스 번호
        file_ref = row.get('file_reference', row.get('file_ref', row.get('mft_entry', '')))
        parent_ref = row.get('parent_reference', row.get('parent_ref', row.get('parent_entry', '')))
        
        if file_ref:
            tags.append('USN_HAS_FILE_REF')
        if parent_ref:
            tags.append('USN_HAS_PARENT_REF')
        
        # Reason 플래그 분석 (변경 이유)
        reason = str(row.get('reason', row.get('reasons', row.get('change_reason', '')))).upper()
        
        # 파일 생성/삭제
        if 'FILE_CREATE' in reason or 'DATA_EXTEND' in reason and 'CLOSE' in reason:
            tags.append('USN_FILE_CREATE')
        if 'FILE_DELETE' in reason:
            tags.append('USN_FILE_DELETE')
            tags.append('SEC_FILE_DELETED')
        
        # 데이터 변경
        if 'DATA_OVERWRITE' in reason:
            tags.append('USN_DATA_OVERWRITE')
        if 'DATA_EXTEND' in reason:
            tags.append('USN_DATA_EXTEND')
        if 'DATA_TRUNCATION' in reason:
            tags.append('USN_DATA_TRUNCATION')
        
        # 이름 변경
        if 'RENAME_OLD' in reason or 'RENAME_OLD_NAME' in reason:
            tags.append('USN_RENAME_OLD')
        if 'RENAME_NEW' in reason or 'RENAME_NEW_NAME' in reason:
            tags.append('USN_RENAME_NEW')
        
        # 보안 변경
        if 'SECURITY_CHANGE' in reason:
            tags.append('USN_SECURITY_CHANGE')
            tags.append('SEC_SECURITY_MODIFIED')
        
        # 속성 변경
        if 'BASIC_INFO_CHANGE' in reason:
            tags.append('USN_BASIC_INFO_CHANGE')
        if 'EA_CHANGE' in reason:
            tags.append('USN_EA_CHANGE')
        if 'NAMED_DATA_EXTEND' in reason or 'NAMED_DATA_OVERWRITE' in reason:
            tags.append('USN_ADS_MODIFIED')
        
        # 압축/암호화
        if 'COMPRESSION_CHANGE' in reason:
            tags.append('USN_COMPRESSION_CHANGE')
        if 'ENCRYPTION_CHANGE' in reason:
            tags.append('USN_ENCRYPTION_CHANGE')
        
        # 하드링크
        if 'HARD_LINK_CHANGE' in reason:
            tags.append('USN_HARDLINK_CHANGE')
        
        # 스트림 변경
        if 'STREAM_CHANGE' in reason:
            tags.append('USN_STREAM_CHANGE')
        
        # 닫기 이벤트
        if 'CLOSE' in reason:
            tags.append('USN_FILE_CLOSE')
        
        # 파일 속성
        attributes = str(row.get('file_attributes', row.get('attributes', ''))).upper()
        if 'DIRECTORY' in attributes:
            tags.append('USN_DIRECTORY')
        if 'ENCRYPTED' in attributes:
            tags.append('USN_ENCRYPTED')
        if 'HIDDEN' in attributes:
            tags.append('USN_HIDDEN')
        if 'SYSTEM' in attributes:
            tags.append('USN_SYSTEM')
        if 'TEMPORARY' in attributes:
            tags.append('USN_TEMPORARY')
        if 'COMPRESSED' in attributes:
            tags.append('USN_COMPRESSED')
        if 'OFFLINE' in attributes:
            tags.append('USN_OFFLINE')
        if 'REPARSE_POINT' in attributes:
            tags.append('USN_REPARSE_POINT')
        if 'SPARSE' in attributes:
            tags.append('USN_SPARSE_FILE')
        
        # 소스 정보
        source_info = str(row.get('source_info', row.get('source', ''))).upper()
        if 'DATA_MANAGEMENT' in source_info:
            tags.append('USN_SOURCE_DATA_MGMT')
        if 'AUXILIARY_DATA' in source_info:
            tags.append('USN_SOURCE_AUX_DATA')
        if 'REPLICATION_MANAGEMENT' in source_info:
            tags.append('USN_SOURCE_REPLICATION')
        
        # 타임스탬프 분석
        timestamp = row.get('timestamp', row.get('time', row.get('date_time', '')))
        if timestamp:
            tags.extend(self._tag_timeline_single(timestamp))
        
        # 의심스러운 활동 패턴
        filename = row.get('filename', row.get('name', ''))
        if filename:
            # 삭제 후 즉시 재생성 (안티포렌식)
            if 'FILE_DELETE' in reason or 'FILE_CREATE' in reason:
                tags.append('USN_POTENTIAL_ANTIFORENSICS')
            
            # 시스템 파일 수정
            if any(sys in str(filename).lower() for sys in ['system32', 'drivers', 'boot']):
                if any(r in reason for r in ['OVERWRITE', 'DELETE', 'SECURITY_CHANGE']):
                    tags.append('USN_SYSTEM_FILE_MODIFIED')
                    tags.append('SEC_CRITICAL_FILE_CHANGE')
        
        return tags

    # ==================== VSS (볼륨 섀도우 복사본) 전용 태거 ====================
    def tag_vss(self, row):
        """볼륨 섀도우 복사본 전용 태깅"""
        tags = ['ARTIFACT_VSS']
        
        # Shadow Copy ID
        shadow_id = row.get('shadow_copy_id', row.get('shadow_id', row.get('vss_id', '')))
        if shadow_id:
            tags.append('VSS_HAS_ID')
        
        # 생성 시간 분석
        creation_time = row.get('creation_time', row.get('created', row.get('install_date', '')))
        if creation_time:
            try:
                created = self._parse_time(creation_time)
                if created:
                    time_diff = datetime.now() - created
                    if time_diff <= timedelta(hours=24):
                        tags.append('VSS_CREATED_24H')
                    elif time_diff <= timedelta(days=7):
                        tags.append('VSS_CREATED_WEEK')
                    elif time_diff <= timedelta(days=30):
                        tags.append('VSS_CREATED_MONTH')
                    else:
                        tags.append('VSS_CREATED_OLD')
            except:
                pass
        
        # Shadow Copy 타입
        shadow_type = str(row.get('type', row.get('shadow_type', ''))).upper()
        if 'CLIENT_ACCESSIBLE' in shadow_type:
            tags.append('VSS_CLIENT_ACCESSIBLE')
        if 'NO_AUTO_RELEASE' in shadow_type:
            tags.append('VSS_PERSISTENT')
        if 'NO_WRITERS' in shadow_type:
            tags.append('VSS_NO_WRITERS')
        if 'DIFFERENTIAL' in shadow_type:
            tags.append('VSS_DIFFERENTIAL')
        if 'PLEX' in shadow_type:
            tags.append('VSS_PLEX')
        
        # 속성 플래그
        attributes = str(row.get('attributes', row.get('flags', ''))).upper()
        if 'PERSISTENT' in attributes:
            tags.append('VSS_PERSISTENT')
        if 'NO_AUTO_RELEASE' in attributes:
            tags.append('VSS_NO_AUTO_RELEASE')
        if 'EXPOSED' in attributes:
            tags.append('VSS_EXPOSED')
        if 'HARDWARE_ASSISTED' in attributes:
            tags.append('VSS_HARDWARE_ASSISTED')
        if 'IMPORTED' in attributes:
            tags.append('VSS_IMPORTED')
        if 'TRANSPORTABLE' in attributes:
            tags.append('VSS_TRANSPORTABLE')
        
        # 원본 볼륨
        origin_volume = row.get('origin_volume', row.get('original_volume', ''))
        if origin_volume:
            tags.append('VSS_HAS_ORIGIN')
        
        # 디바이스 경로
        device_path = row.get('device_object', row.get('device_path', ''))
        if 'harddiskvolumeshadowcopy' in str(device_path).lower():
            tags.append('VSS_DEVICE_PATH_VALID')
        
        # 공급자 (Provider)
        provider = str(row.get('provider', row.get('provider_id', ''))).upper()
        if 'MICROSOFT' in provider or 'SOFTWARE' in provider:
            tags.append('VSS_SOFTWARE_PROVIDER')
        if 'SYSTEM' in provider:
            tags.append('VSS_SYSTEM_PROVIDER')
        
        # 상태
        state = str(row.get('state', row.get('status', ''))).upper()
        if 'CREATED' in state or 'ACTIVE' in state:
            tags.append('VSS_ACTIVE')
        if 'DELETED' in state or 'REMOVING' in state:
            tags.append('VSS_DELETED')
        if 'PREPARING' in state:
            tags.append('VSS_PREPARING')
        
        # 파일 경로 분석 (VSS 내 파일인 경우)
        filepath = row.get('filepath', row.get('path', row.get('full_path', '')))
        if 'harddiskvolumeshadowcopy' in str(filepath).lower():
            tags.append('VSS_FILE_FROM_SHADOW')
            
            # Shadow Copy 번호 추출
            match = re.search(r'harddiskvolumeshadowcopy(\d+)', str(filepath), re.IGNORECASE)
            if match:
                shadow_num = int(match.group(1))
                if shadow_num > 10:
                    tags.append('VSS_HIGH_COPY_NUMBER')
        
        # 용량 분석
        size = row.get('size', row.get('used_space', row.get('allocated_space', '')))
        max_size = row.get('max_space', row.get('maximum_size', ''))
        
        try:
            if size:
                size_val = int(str(size).replace(',', '').replace(' ', ''))
                if size_val > 10 * 1024 * 1024 * 1024:  # > 10GB
                    tags.append('VSS_LARGE_SIZE')
            
            if size and max_size:
                size_val = int(str(size).replace(',', '').replace(' ', ''))
                max_val = int(str(max_size).replace(',', '').replace(' ', ''))
                usage = (size_val / max_val) * 100 if max_val > 0 else 0
                if usage > 80:
                    tags.append('VSS_HIGH_USAGE')
        except:
            pass
        
        # 보안 관련 - 의심스러운 VSS 활동
        if 'VSS_DELETED' in tags or 'VSS_REMOVING' in tags:
            tags.append('SEC_VSS_DELETED')
        
        # 최근 생성된 VSS (랜섬웨어는 종종 VSS 삭제)
        if 'VSS_CREATED_24H' in tags or 'VSS_CREATED_WEEK' in tags:
            tags.append('VSS_RECENT_ACTIVITY')
        
        return tags

    # ==================== 공통 유틸리티 메서드 ====================
    def _parse_time(self, time_str):
        """다양한 시간 형식 파싱"""
        if not time_str or str(time_str).strip().upper() in ['N/A', 'NULL', '', 'NONE', '0']:
            return None
        
        time_str = str(time_str).strip()
        
        # ISO 형식
        try:
            return datetime.fromisoformat(time_str.replace('Z', '+00:00').split('+')[0].split('.')[0])
        except:
            pass
        
        # 일반 형식들
        formats = [
            '%Y-%m-%d %H:%M:%S',
            '%Y/%m/%d %H:%M:%S',
            '%m/%d/%Y %H:%M:%S',
            '%d/%m/%Y %H:%M:%S',
            '%Y-%m-%d',
            '%Y/%m/%d',
            '%m/%d/%Y',
            '%d/%m/%Y'
        ]
        
        for fmt in formats:
            try:
                return datetime.strptime(time_str.split('.')[0], fmt)
            except:
                continue
        
        return None

    def _tag_timeline_single(self, timestamp):
        """단일 타임스탬프 태깅"""
        tags = []
        try:
            time_obj = self._parse_time(timestamp)
            if time_obj:
                time_diff = datetime.now() - time_obj
                if time_diff <= timedelta(hours=24):
                    tags.append('TIME_LAST_24H')
                elif time_diff <= timedelta(days=7):
                    tags.append('TIME_LAST_WEEK')
                elif time_diff <= timedelta(days=30):
                    tags.append('TIME_LAST_MONTH')
                elif time_diff <= timedelta(days=90):
                    tags.append('TIME_LAST_3MONTHS')
        except:
            pass
        return tags

    # ==================== 기본 태거 메서드들 ====================
    def tag_file_format(self, filename):
        """파일 포맷 태그"""
        tags = []
        ext = Path(str(filename)).suffix.lower()
        for format_tag, extensions in self.format_map.items():
            if ext in extensions:
                tags.append(format_tag)
        return tags

    def tag_system_area(self, filepath):
        """시스템 영역 태그"""
        tags = []
        for area_tag, pattern in self.area_patterns.items():
            if re.search(pattern, str(filepath)):
                tags.append(area_tag)
        return tags

    def tag_security(self, filepath, filename):
        """보안 관련 태그"""
        tags = []
        full_path = str(filepath) + str(filename)
        
        for sec_tag, pattern in self.security_patterns.items():
            if re.search(pattern, full_path):
                tags.append(sec_tag)
        
        return tags

    # ==================== 메인 처리 메서드 ====================
    def detect_artifact_type(self, row):
        """CSV 구조 분석하여 아티팩트 타입 자동 감지"""
        columns = [str(c).lower() for c in row.keys()]
        columns_str = ' '.join(columns)
        
        # MFT 엔트리 감지
        if any(k in columns_str for k in ['mft_entry', 'entry_number', 'file_reference', 'sequence']):
            if any(k in columns_str for k in ['$standard_information', '$file_name', 'si_', 'fn_']):
                return 'mft'
        
        # USN 저널 감지
        if any(k in columns_str for k in ['usn', 'update_sequence', 'reason', 'source_info']):
            if any(k in columns_str for k in ['file_reference', 'parent_reference']):
                return 'usn'
        
        # VSS 감지
        if any(k in columns_str for k in ['shadow_copy', 'vss', 'harddiskvolumeshadowcopy']):
            return 'vss'
        if any(k in columns_str for k in ['shadow_id', 'creation_time', 'origin_volume']):
            return 'vss'
        
        # 기본: 파일 시스템
        return 'filesystem'

    def process_csv(self, input_csv, output_csv, artifact_type=None):
        """CSV 처리 메인 메서드"""
        results = []
        original_fieldnames = []
        detected_type = None
        
        with open(input_csv, 'r', encoding='utf-8-sig') as f:
            reader = csv.DictReader(f)
            original_fieldnames = reader.fieldnames
            
            for idx, row in enumerate(reader):
                # 첫 번째 행에서 타입 자동 감지
                if idx == 0 and not artifact_type:
                    detected_type = self.detect_artifact_type(row)
                    print(f"🔍 자동 감지된 아티팩트 타입: {detected_type.upper()}")
                
                current_type = artifact_type or detected_type or 'filesystem'
                
                # 타입별 전용 태거 호출
                tags = []
                if current_type == 'mft':
                    tags.extend(self.tag_mft_entry(row))
                elif current_type == 'usn':
                    tags.extend(self.tag_usn_journal(row))
                elif current_type == 'vss':
                    tags.extend(self.tag_vss(row))
                
                # 공통 태그 추가
                filename = row.get('filename', row.get('name', row.get('file_name', '')))
                filepath = row.get('filepath', row.get('path', row.get('file_path', '')))
                
                if filename:
                    tags.extend(self.tag_file_format(filename))
                if filepath:
                    tags.extend(self.tag_system_area(filepath))
                    if filename:
                        tags.extend(self.tag_security(filepath, filename))
                
                # 중복 제거 및 정렬
                tags = sorted(list(set(tags)))
                
                # 결과 저장
                result_row = row.copy()
                result_row['tags'] = ', '.join(tags)
                results.append(result_row)
        
        # CSV 저장
        if results:
            new_fieldnames = list(original_fieldnames) + ['tags']
            with open(output_csv, 'w', encoding='utf-8-sig', newline='') as f:
                writer = csv.DictWriter(f, fieldnames=new_fieldnames)
                writer.writeheader()
                writer.writerows(results)
        
        print(f"✅ 처리 완료: {len(results)}개 항목")
        print(f"📁 출력 파일: {output_csv}")
        self.print_statistics(results)
        
        return results

    def print_statistics(self, results):
        """통계 출력"""
        tag_counts = {}
        for result in results:
            tags_str = result.get('tags', '')
            if tags_str:
                for tag in [t.strip() for t in tags_str.split(',')]:
                    if tag:
                        tag_counts[tag] = tag_counts.get(tag, 0) + 1
        
        print(f"\n{'='*60}")
        print("📊 상위 30개 태그")
        print(f"{'='*60}")
        for tag, count in sorted(tag_counts.items(), key=lambda x: x[1], reverse=True)[:30]:
            print(f"  {tag:40} : {count:5} 개")


# =====================================================================
# 아래부터: main.py와 동일 드라이브 기준으로 BASE_OUT 찾고,
# 각 드라이브 루트 밑에 tag 폴더를 만들어서 태깅 수행
# =====================================================================

def _existing_data_drives():
    """C:를 제외한 실제 존재하는 드라이브 목록 (D:~Z:)"""
    drives = []
    for code in range(ord("D"), ord("Z") + 1):
        root = Path(f"{chr(code)}:\\")
        if root.exists():
            drives.append(chr(code))
    return drives

def resolve_e01_path():
    """
    main.py와 비슷하게, D:~Z: 각 드라이브의 \\ccit\\*.e01 중 첫 번째를 사용.
    (환경변수는 사용 안 함 – 승원이 말대로)
    """
    candidates = []
    for d in _existing_data_drives():
        ccit_root = Path(f"{d}:\\ccit")
        if not ccit_root.is_dir():
            continue
        try:
            for hit in ccit_root.rglob("*.e01"):
                candidates.append(hit)
        except Exception as e:
            print(f"[WARN] {ccit_root} 검색 중 예외 발생: {e}")

    if not candidates:
        print("[ERR ] E01 이미지를 찾지 못했습니다. (D:~Z:\\ccit\\*.e01 없음)")
        return None

    # 드라이브/경로 순으로 정렬 후 첫 번째 사용
    candidates = sorted(candidates, key=lambda p: (p.drive, str(p).lower()))
    chosen = candidates[0]
    print(f"[INFO] 태깅 기준 E01: {chosen}")
    return chosen

def find_base_out_from_e01():
    """
    main.py와 동일 규칙:
    BASE_OUT = <E01가 있는 드라이브>:\\Kape Output
    """
    e01 = resolve_e01_path()
    if not e01:
        return None
    drive = e01.drive or "D:"
    base_out = Path(drive + r"\Kape Output")
    if not base_out.is_dir():
        print(f"[ERR ] BASE_OUT 폴더가 존재하지 않습니다: {base_out}")
        return None
    print(f"[INFO] BASE_OUT: {base_out}")
    return base_out

def main():
    base_out = find_base_out_from_e01()
    if not base_out:
        return

    tagger = ExtendedArtifactTagger()

    # BASE_OUT 아래의 각 드라이브 루트(H, E 등)를 순회
    for drive_root in sorted(p for p in base_out.iterdir() if p.is_dir()):
        print(f"\n[DRIVE] 태깅 대상 드라이브 루트: {drive_root}")
        tag_root = drive_root / "tag"
        tag_root.mkdir(parents=True, exist_ok=True)

        # drive_root 이하 모든 CSV 탐색
        for csv_path in drive_root.rglob("*.csv"):
            # 이미 tag 폴더 안에 있는 건 스킵
            if tag_root in csv_path.parents:
                continue
            # 이미 _tagged.csv 로 끝나는 것도 스킵 (원본만 대상으로)
            if csv_path.stem.endswith("_tagged"):
                continue

            # drive_root 기준 상대 경로를 유지하면서 tag 밑에 동일 구조 생성
            rel_path = csv_path.relative_to(drive_root)  # 예: AmcacheParser\...\foo.csv
            out_path = tag_root / rel_path.parent / (csv_path.stem + "_tagged.csv")
            out_path.parent.mkdir(parents=True, exist_ok=True)

            print(f"\n[STEP] CSV 태깅: {csv_path} -> {out_path}")
            try:
                tagger.process_csv(str(csv_path), str(out_path))
            except UnicodeDecodeError as e:
                print(f"[SKIP] 디코딩 오류로 스킵: {csv_path} ({e})")
            except Exception as e:
                print(f"[ERR ] 태깅 중 예외 발생, 스킵: {csv_path} ({e})")

if __name__ == "__main__":
    main()
