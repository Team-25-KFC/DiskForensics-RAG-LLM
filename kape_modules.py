"""
개별 아티팩트 파서 모듈
각 아티팩트를 독립적으로 실행 가능
"""

from kape_parser import KAPEParser, KAPE_EXE, MOUNTED_DRIVE, OUTPUT_BASE


def parse_registry_system():
    """Registry System Hives (SYSTEM, SOFTWARE, SAM, SECURITY)"""
    parser = KAPEParser(KAPE_EXE, MOUNTED_DRIVE, OUTPUT_BASE)
    return parser.parse_artifact("registry_system")


def parse_registry_user():
    """Registry User Hives (NTUSER.DAT)"""
    parser = KAPEParser(KAPE_EXE, MOUNTED_DRIVE, OUTPUT_BASE)
    return parser.parse_artifact("registry_user")


def parse_event_logs():
    """Windows Event Logs"""
    parser = KAPEParser(KAPE_EXE, MOUNTED_DRIVE, OUTPUT_BASE)
    return parser.parse_artifact("event_logs")


def parse_mft():
    """$MFT (Master File Table)"""
    parser = KAPEParser(KAPE_EXE, MOUNTED_DRIVE, OUTPUT_BASE)
    return parser.parse_artifact("mft")


def parse_logfile():
    """$LogFile"""
    parser = KAPEParser(KAPE_EXE, MOUNTED_DRIVE, OUTPUT_BASE)
    return parser.parse_artifact("logfile")


def parse_recycle_bin():
    """$Recycle.Bin"""
    parser = KAPEParser(KAPE_EXE, MOUNTED_DRIVE, OUTPUT_BASE)
    return parser.parse_artifact("recycle_bin")


def parse_prefetch():
    """Windows Prefetch"""
    parser = KAPEParser(KAPE_EXE, MOUNTED_DRIVE, OUTPUT_BASE)
    return parser.parse_artifact("prefetch")


def parse_startup():
    """Startup Folders"""
    parser = KAPEParser(KAPE_EXE, MOUNTED_DRIVE, OUTPUT_BASE)
    return parser.parse_artifact("startup")


def parse_browser():
    """Web Browsers (IE, Chrome, Firefox, Edge)"""
    parser = KAPEParser(KAPE_EXE, MOUNTED_DRIVE, OUTPUT_BASE)
    return parser.parse_artifact("browser")


# 사용 예제
if __name__ == "__main__":
    import sys
    
    if len(sys.argv) < 2:
        print("사용법: python kape_modules.py [artifact_name]")
        print("\n사용 가능한 아티팩트:")
        print("  - registry_system   : Registry System Hives")
        print("  - registry_user     : Registry User Hives (NTUSER.DAT)")
        print("  - event_logs        : Windows Event Logs")
        print("  - mft               : $MFT")
        print("  - logfile           : $LogFile")
        print("  - recycle_bin       : $Recycle.Bin")
        print("  - prefetch          : Prefetch")
        print("  - startup           : Startup Folders")
        print("  - browser           : Web Browsers")
        print("\n예제:")
        print("  python kape_modules.py registry_system")
        print("  python kape_modules.py prefetch")
        sys.exit(1)
    
    artifact = sys.argv[1]
    
    # 함수 매핑
    functions = {
        "registry_system": parse_registry_system,
        "registry_user": parse_registry_user,
        "event_logs": parse_event_logs,
        "mft": parse_mft,
        "logfile": parse_logfile,
        "recycle_bin": parse_recycle_bin,
        "prefetch": parse_prefetch,
        "startup": parse_startup,
        "browser": parse_browser,
    }
    
    if artifact not in functions:
        print(f"✗ 알 수 없는 아티팩트: {artifact}")
        sys.exit(1)
    
    # 실행
    print(f"{'=' * 60}")
    print(f"아티팩트 파싱: {artifact}")
    print(f"{'=' * 60}\n")
    
    result = functions[artifact]()
    
    if result['success']:
        print(f"\n✓ 파싱 성공!")
        print(f"  Target 출력: {result['tdest']}")
        print(f"  Module 출력: {result['mdest']}")
    else:
        print(f"\n✗ 파싱 실패: {result['message']}")
        sys.exit(1)
