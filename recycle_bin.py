import os
import json
import datetime
import struct
from pathlib import Path

# ==================== 설정 ====================
# 마운트된 드라이브 경로 (예: E:, F: 등)
MOUNTED_DRIVE = "G:"  # 마운트된 드라이브 문자로 변경

# 휴지통 경로
RECYCLE_BIN_PATH = r"$Recycle.Bin"

# 출력 파일
OUTPUT_FILE = "recycle_bin_artifacts.jsonl"
# =============================================


class RecycleBinParser:
    def __init__(self, drive_letter):
        """
        휴지통 파서 초기화
        
        Args:
            drive_letter: 마운트된 드라이브 문자 (예: "E:")
        """
        self.drive = drive_letter.rstrip("\\")
        self.artifacts = []
        
    def get_file_metadata(self, file_path):
        """
        파일의 메타데이터 추출
        
        Args:
            file_path: 파일 경로
            
        Returns:
            dict: 파일 메타데이터
        """
        try:
            stat_info = os.stat(file_path)
            
            # 파일 시간 정보
            created = datetime.datetime.fromtimestamp(stat_info.st_ctime).isoformat()
            modified = datetime.datetime.fromtimestamp(stat_info.st_mtime).isoformat()
            accessed = datetime.datetime.fromtimestamp(stat_info.st_atime).isoformat()
            
            return {
                'created': created,
                'modified': modified,
                'accessed': accessed,
                'size': stat_info.st_size,
            }
        except Exception as e:
            return {
                'created': None,
                'modified': None,
                'accessed': None,
                'size': None,
                'error': str(e)
            }
    
    def parse_i_file(self, i_file_path):
        """
        $I 파일 파싱 (Windows Vista 이상)
        
        $I 파일 구조:
        - Version (8 bytes)
        - Original file size (8 bytes)
        - Deletion time (8 bytes, FILETIME)
        - Original file path (variable length, Unicode)
        
        Args:
            i_file_path: $I 파일 경로
            
        Returns:
            dict: 파싱된 정보
        """
        try:
            with open(i_file_path, 'rb') as f:
                # 헤더 읽기
                header = f.read(8)
                
                # Version 확인 (Windows Vista 이상은 version 1 또는 2)
                version = struct.unpack('<Q', header)[0]
                
                # 원본 파일 크기 (8 bytes)
                original_size_bytes = f.read(8)
                original_size = struct.unpack('<Q', original_size_bytes)[0]
                
                # 삭제 시간 (8 bytes, FILETIME format)
                deletion_time_bytes = f.read(8)
                deletion_time_raw = struct.unpack('<Q', deletion_time_bytes)[0]
                
                # FILETIME을 datetime으로 변환
                # FILETIME: 1601년 1월 1일부터의 100-nanosecond 간격
                try:
                    deletion_time = self._filetime_to_datetime(deletion_time_raw)
                except:
                    deletion_time = None
                
                # 원본 파일 경로 (나머지 부분, Unicode)
                path_bytes = f.read()
                
                # Unicode 디코딩 (null-terminated)
                try:
                    original_path = path_bytes.decode('utf-16-le').rstrip('\x00')
                except:
                    original_path = "Unknown"
                
                return {
                    'version': version,
                    'original_size': original_size,
                    'deletion_time': deletion_time.isoformat() if deletion_time else None,
                    'original_path': original_path,
                    'parsed': True
                }
        
        except Exception as e:
            return {
                'error': str(e),
                'parsed': False
            }
    
    def _filetime_to_datetime(self, filetime):
        """
        Windows FILETIME을 datetime으로 변환
        
        Args:
            filetime: FILETIME 값
            
        Returns:
            datetime: 변환된 datetime 객체
        """
        # FILETIME epoch: 1601-01-01
        epoch = datetime.datetime(1601, 1, 1)
        
        # 100-nanosecond 간격을 초로 변환
        seconds = filetime / 10000000.0
        
        return epoch + datetime.timedelta(seconds=seconds)
    
    def scan_recycle_bin(self):
        """
        휴지통 폴더 스캔
        
        Returns:
            list: 발견된 아티팩트 목록
        """
        artifacts = []
        recycle_bin_path = os.path.join(self.drive, RECYCLE_BIN_PATH)
        
        if not os.path.exists(recycle_bin_path):
            print(f"⚠ 경로 없음: {recycle_bin_path}")
            return artifacts
        
        print(f"✓ 스캔 중: {recycle_bin_path}\n")
        
        try:
            # SID 폴더 순회
            for sid_folder in os.listdir(recycle_bin_path):
                sid_path = os.path.join(recycle_bin_path, sid_folder)
                
                # 디렉토리만 처리
                if not os.path.isdir(sid_path):
                    continue
                
                print(f"  SID: {sid_folder}")
                
                # SID 폴더 내부 파일 스캔
                try:
                    files_in_sid = os.listdir(sid_path)
                    
                    # $I 파일과 $R 파일 매칭
                    i_files = [f for f in files_in_sid if f.startswith('$I')]
                    r_files = [f for f in files_in_sid if f.startswith('$R')]
                    
                    print(f"    → $I 파일: {len(i_files)}개, $R 파일: {len(r_files)}개")
                    
                    for i_file in i_files:
                        i_file_path = os.path.join(sid_path, i_file)
                        
                        # $I 파일 파싱
                        i_file_info = self.parse_i_file(i_file_path)
                        i_file_metadata = self.get_file_metadata(i_file_path)
                        
                        # 대응하는 $R 파일 찾기
                        r_file = i_file.replace('$I', '$R')
                        r_file_path = os.path.join(sid_path, r_file)
                        
                        r_file_exists = os.path.exists(r_file_path)
                        r_file_metadata = None
                        
                        if r_file_exists:
                            r_file_metadata = self.get_file_metadata(r_file_path)
                        
                        # 아티팩트 생성
                        artifact = {
                            'artifact_type': 'recycle_bin',
                            'sid': sid_folder,
                            'i_file': i_file,
                            'i_file_path': i_file_path,
                            'i_file_created': i_file_metadata.get('created'),
                            'i_file_modified': i_file_metadata.get('modified'),
                            'i_file_accessed': i_file_metadata.get('accessed'),
                            'r_file': r_file if r_file_exists else None,
                            'r_file_path': r_file_path if r_file_exists else None,
                            'r_file_exists': r_file_exists,
                            'original_filename': os.path.basename(i_file_info.get('original_path', 'Unknown')),
                            'original_path': i_file_info.get('original_path'),
                            'original_size': i_file_info.get('original_size'),
                            'deletion_time': i_file_info.get('deletion_time'),
                            'current_size': r_file_metadata.get('size') if r_file_metadata else None,
                            'parsed_successfully': i_file_info.get('parsed', False),
                            'timestamp': datetime.datetime.now().isoformat()
                        }
                        
                        artifacts.append(artifact)
                        
                        # 상세 정보 출력
                        print(f"      [{i_file}]")
                        if i_file_info.get('parsed'):
                            print(f"        원본: {i_file_info.get('original_path')}")
                            print(f"        크기: {i_file_info.get('original_size')} bytes")
                            print(f"        삭제: {i_file_info.get('deletion_time')}")
                
                except PermissionError:
                    print(f"    ✗ 권한 없음: {sid_path}")
                except Exception as e:
                    print(f"    ✗ 오류: {e}")
        
        except PermissionError:
            print(f"✗ 권한 없음: {recycle_bin_path}")
        except Exception as e:
            print(f"✗ 오류 [{recycle_bin_path}]: {e}")
        
        return artifacts
    
    def parse_all(self):
        """
        휴지통 아티팩트 파싱
        
        Returns:
            list: 모든 아티팩트 목록
        """
        print("=" * 60)
        print("휴지통 아티팩트 파싱 시작")
        print("=" * 60)
        print(f"마운트된 드라이브: {self.drive}\n")
        
        artifacts = self.scan_recycle_bin()
        
        print("\n" + "=" * 60)
        print(f"총 {len(artifacts)}개의 아티팩트 발견")
        print("=" * 60)
        
        return artifacts
    
    def save_to_jsonl(self, artifacts, output_file):
        """
        아티팩트를 JSONL 형식으로 저장
        
        Args:
            artifacts: 아티팩트 목록
            output_file: 출력 파일 경로
        """
        try:
            with open(output_file, 'w', encoding='utf-8') as f:
                for artifact in artifacts:
                    json_line = json.dumps(artifact, ensure_ascii=False)
                    f.write(json_line + '\n')
            
            print(f"\n✓ 저장 완료: {output_file}")
            print(f"✓ 총 {len(artifacts)}개 레코드 저장")
            
            # 통계 정보
            total_original_size = sum(a.get('original_size', 0) or 0 for a in artifacts)
            parsed_count = sum(1 for a in artifacts if a.get('parsed_successfully'))
            
            print(f"\n[통계]")
            print(f"  - 파싱 성공: {parsed_count}/{len(artifacts)}개")
            print(f"  - 원본 파일 총 크기: {total_original_size:,} bytes ({total_original_size / (1024*1024):.2f} MB)")
            
        except Exception as e:
            print(f"\n✗ 저장 실패: {e}")


def main():
    """
    휴지통 아티팩트 파싱 메인 함수
    """
    # 파서 초기화
    parser = RecycleBinParser(MOUNTED_DRIVE)
    
    # 휴지통 아티팩트 파싱
    artifacts = parser.parse_all()
    
    # JSONL 파일로 저장
    if artifacts:
        parser.save_to_jsonl(artifacts, OUTPUT_FILE)
        
        # 샘플 출력
        print("\n" + "=" * 60)
        print("샘플 레코드 (첫 3개)")
        print("=" * 60)
        for i, artifact in enumerate(artifacts[:3], 1):
            print(f"\n[{i}] {artifact.get('original_filename', 'Unknown')}")
            print(json.dumps(artifact, indent=2, ensure_ascii=False))
    else:
        print("\n⚠ 발견된 아티팩트가 없습니다.")


if __name__ == "__main__":
    main()
