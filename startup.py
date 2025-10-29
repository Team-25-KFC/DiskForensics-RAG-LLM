import os
import json
import datetime
from pathlib import Path
import win32file
import pywintypes

# ==================== 설정 ====================
# 마운트된 드라이브 경로 (예: E:, F: 등)
MOUNTED_DRIVE = "G:"  # 마운트된 드라이브 문자로 변경

# Startup 폴더 경로들
STARTUP_PATHS = [
    r"ProgramData\Microsoft\Windows\Start Menu\Programs\Startup",
    r"Users\*\AppData\Roaming\Microsoft\Windows\Start Menu\Programs\Startup",
]

# 출력 파일
OUTPUT_FILE = "startup_artifacts.jsonl"
# =============================================


class StartupParser:
    def __init__(self, drive_letter):
        """
        Startup 폴더 파서 초기화
        
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
    
    def parse_lnk_file(self, lnk_path):
        """
        LNK 파일 파싱 (기본 정보만)
        
        Args:
            lnk_path: LNK 파일 경로
            
        Returns:
            dict: LNK 파일 정보
        """
        try:
            # LNK 파일의 기본 정보
            # 실제 타겟 경로는 복잡한 파싱이 필요하므로 여기서는 기본 정보만
            return {
                'type': 'lnk',
                'name': os.path.basename(lnk_path),
                'path': lnk_path,
            }
        except Exception as e:
            return {
                'type': 'lnk',
                'name': os.path.basename(lnk_path),
                'path': lnk_path,
                'error': str(e)
            }
    
    def scan_startup_folder(self, folder_path):
        """
        Startup 폴더 스캔
        
        Args:
            folder_path: 스캔할 폴더 경로
            
        Returns:
            list: 발견된 아티팩트 목록
        """
        artifacts = []
        
        # 절대 경로 생성
        full_path = os.path.join(self.drive, folder_path)
        
        # 와일드카드(*) 처리
        if '*' in folder_path:
            # Users\*\... 형태 처리
            base_path = folder_path.split('*')[0]
            pattern = folder_path.split('*')[1]
            
            users_path = os.path.join(self.drive, base_path.strip('\\'))
            
            if os.path.exists(users_path):
                try:
                    for user_dir in os.listdir(users_path):
                        user_startup_path = os.path.join(users_path, user_dir, pattern.strip('\\'))
                        
                        if os.path.exists(user_startup_path):
                            artifacts.extend(self._scan_directory(user_startup_path, user_dir))
                except Exception as e:
                    print(f"✗ 오류 [{users_path}]: {e}")
        else:
            # 일반 경로 처리
            if os.path.exists(full_path):
                artifacts.extend(self._scan_directory(full_path, "All Users"))
            else:
                print(f"⚠ 경로 없음: {full_path}")
        
        return artifacts
    
    def _scan_directory(self, directory, user_context):
        """
        디렉토리 내부 파일 스캔
        
        Args:
            directory: 스캔할 디렉토리
            user_context: 사용자 컨텍스트 (예: "Administrator", "All Users")
            
        Returns:
            list: 발견된 아티팩트 목록
        """
        artifacts = []
        
        try:
            print(f"✓ 스캔 중: {directory}")
            
            for item in os.listdir(directory):
                item_path = os.path.join(directory, item)
                
                if os.path.isfile(item_path):
                    # 파일 메타데이터 추출
                    metadata = self.get_file_metadata(item_path)
                    
                    artifact = {
                        'artifact_type': 'startup',
                        'user': user_context,
                        'file_name': item,
                        'file_path': item_path,
                        'file_extension': os.path.splitext(item)[1].lower(),
                        'created_time': metadata.get('created'),
                        'modified_time': metadata.get('modified'),
                        'accessed_time': metadata.get('accessed'),
                        'file_size': metadata.get('size'),
                        'timestamp': datetime.datetime.now().isoformat()
                    }
                    
                    # LNK 파일인 경우 추가 정보
                    if item.lower().endswith('.lnk'):
                        lnk_info = self.parse_lnk_file(item_path)
                        artifact['lnk_info'] = lnk_info
                    
                    artifacts.append(artifact)
                    print(f"  → 발견: {item}")
        
        except PermissionError:
            print(f"✗ 권한 없음: {directory}")
        except Exception as e:
            print(f"✗ 오류 [{directory}]: {e}")
        
        return artifacts
    
    def parse_all(self):
        """
        모든 Startup 폴더 파싱
        
        Returns:
            list: 모든 아티팩트 목록
        """
        print("=" * 60)
        print("Startup 폴더 아티팩트 파싱 시작")
        print("=" * 60)
        print(f"마운트된 드라이브: {self.drive}\n")
        
        all_artifacts = []
        
        for startup_path in STARTUP_PATHS:
            print(f"\n스캔 대상: {startup_path}")
            artifacts = self.scan_startup_folder(startup_path)
            all_artifacts.extend(artifacts)
        
        print("\n" + "=" * 60)
        print(f"총 {len(all_artifacts)}개의 아티팩트 발견")
        print("=" * 60)
        
        return all_artifacts
    
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
            
        except Exception as e:
            print(f"\n✗ 저장 실패: {e}")


def main():
    """
    Startup 폴더 파싱 메인 함수
    """
    # 파서 초기화
    parser = StartupParser(MOUNTED_DRIVE)
    
    # 모든 Startup 폴더 파싱
    artifacts = parser.parse_all()
    
    # JSONL 파일로 저장
    if artifacts:
        parser.save_to_jsonl(artifacts, OUTPUT_FILE)
        
        # 샘플 출력
        print("\n" + "=" * 60)
        print("샘플 레코드 (첫 3개)")
        print("=" * 60)
        for i, artifact in enumerate(artifacts[:3], 1):
            print(f"\n[{i}] {artifact['file_name']}")
            print(json.dumps(artifact, indent=2, ensure_ascii=False))
    else:
        print("\n⚠ 발견된 아티팩트가 없습니다.")


if __name__ == "__main__":
    main()
