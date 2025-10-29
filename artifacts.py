#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""
E01 이미지에서 주요 포렌식 아티팩트(존재 여부 및 간단 메타데이터)를 점검하는 스크립트
출력: 콘솔(표) 및 JSON 파일 (scan_results.json)
주의: 이미지 파일은 읽기 전용으로 열립니다.
"""

import pyewf
import pytsk3
import sys
import os
import json
from datetime import datetime
from tabulate import tabulate

# === 사용자 지정: 검색할 '전형적인' 아티팩트 경로 목록 ===
WINDOWS_ARTIFACT_PATHS = [
    r'\\Windows\\System32\\config\\SYSTEM',
    r'\\Windows\\System32\\config\\SOFTWARE',
    r'\\Windows\\System32\\config\\SAM',
    r'\\Windows\\System32\\config\\SECURITY',
    r'\\Users\\%USERNAME%\\NTUSER.DAT',     # %USERNAME%는 와일드카드 처리
    r'\\Windows\\System32\\winevt\\Logs\\',
    r'\\$MFT',
    r'\\$LogFile',
    r'\\$UsnJrnl:$J',
    r'\\Recycler\\',   # Recycle Bin (구버전)
    r'\\$Recycle.Bin\\', # Recycle Bin (신버전)
    r'\\Program Files\\Google\\Chrome\\User Data\\Default\\History',
    r'\\Users\\%USERNAME%\\AppData\\Roaming\\Mozilla\\Firefox\\Profiles\\',
    r'\\Windows\\Prefetch\\',
    r'\\ProgramData\\Microsoft\\Windows\\Start Menu\\Programs\\Startup\\',
    r'\\Program Files\\Internet Explorer\\',  # IE/Edge 관련
]

LINUX_ARTIFACT_PATHS = [
    '/var/log/',
    '/etc/passwd',
    '/etc/shadow',
    '/home/',
    '/root/',
    '/var/log/auth.log',
    '/var/log/syslog',
]

# === pyewf -> pytsk3 image wrapper ===
class EwfImgInfo(pytsk3.Img_Info):
    def __init__(self, ewf_handle):
        # pytsk3의 Img_Info는 url 인자를 요구함
        self._ewf_handle = ewf_handle
        self._size = self._ewf_handle.get_media_size()
        pytsk3.Img_Info.__init__(self, url="", type=pytsk3.TSK_IMG_TYPE_EXTERNAL)

    def close(self):
        try:
            self._ewf_handle.close()
        except Exception:
            pass

    def read(self, offset, size):
        self._ewf_handle.seek(offset)
        return self._ewf_handle.read(size)

    def get_size(self):
        return self._size


def open_ewf(ewf_path):
    # supports multi-segment E01 naming (e01, e01.1 etc) by using pyewf.glob
    filenames = pyewf.glob(ewf_path)
    ewf_handle = pyewf.handle()
    ewf_handle.open(filenames)
    return ewf_handle

def scan_filesystem(img_info, volume):
    results = []
    # volume: pytsk3.Volume_Info partition object
    try:
        fs = pytsk3.FS_Info(img_info, offset=volume.start * volume.info.block_size)
    except Exception as e:
        # some images may not have partition or raw FS at that offset; try without offset
        try:
            fs = pytsk3.FS_Info(img_info)
        except Exception as e2:
            return results

    # helper: check existence of path (supports simple wildcards for %USERNAME%)
    def check_path_exists(path_pattern):
        hits = []
        # if pattern contains %USERNAME% we need to enumerate Users directory
        if '%USERNAME%' in path_pattern:
            # enumerate common users directory
            try:
                root = fs.open_dir(path="/")
            except Exception:
                return hits
            # simple approach: check under /Users or /home
            user_dirs = []
            for candidate in ['/Users', '/users', '/home']:
                try:
                    d = fs.open_dir(path=candidate)
                    for entry in d:
                        name = entry.info.name.name.decode('utf-8', 'ignore')
                        if name in ['.', '..']:
                            continue
                        user_dirs.append(os.path.join(candidate, name))
                except Exception:
                    continue
            for udir in user_dirs:
                p = path_pattern.replace('%USERNAME%', udir.split(os.sep)[-1])
                # build absolute path: ensure backslashes -> forward (pytsk uses unix-style)
                p2 = p.replace('\\', '/')
                try:
                    f = fs.open(p2)
                    hits.append({'path': p2, 'size': getattr(f.info, 'size', None), 'mtime': getattr(f.info, 'mtime', None)})
                except Exception:
                    # maybe directory
                    try:
                        d = fs.open_dir(p2)
                        hits.append({'path': p2, 'size': None, 'mtime': None})
                    except Exception:
                        pass
            return hits

        p = path_pattern.replace('\\', '/')
        # if pattern ends with slash -> directory check
        try:
            if p.endswith('/'):
                d = fs.open_dir(path=p)
                hits.append({'path': p, 'size': None, 'mtime': None})
            else:
                f = fs.open(path=p)
                hits.append({'path': p, 'size': getattr(f.info, 'size', None), 'mtime': getattr(f.info, 'mtime', None)})
        except Exception:
            pass
        return hits

    # check windows artifact list
    for pat in WINDOWS_ARTIFACT_PATHS:
        found = check_path_exists(pat)
        for h in found:
            results.append({'artifact': pat, 'found_path': h['path'], 'size': h['size'], 'mtime': h['mtime']})
    # check linux artifact list
    for pat in LINUX_ARTIFACT_PATHS:
        p = pat.replace('\\', '/')
        try:
            # directory check
            if p.endswith('/'):
                d = fs.open_dir(path=p)
                results.append({'artifact': pat, 'found_path': p, 'size': None, 'mtime': None})
            else:
                f = fs.open(path=p)
                results.append({'artifact': pat, 'found_path': p, 'size': getattr(f.info, 'size', None), 'mtime': getattr(f.info, 'mtime', None)})
        except Exception:
            pass

    # additionally check root MFT presence for NTFS
    try:
        fs_type = fs.info.ftype
        # pytsk3 doesn't expose nice string; attempt to open $MFT by name
        try:
            f = fs.open(path="/$MFT")
            results.append({'artifact': '$MFT', 'found_path': '/$MFT', 'size': getattr(f.info, 'size', None), 'mtime': getattr(f.info, 'mtime', None)})
        except Exception:
            pass
    except Exception:
        pass

    return results

def scan_image(ewf_path):
    ewf_handle = open_ewf(ewf_path)
    img_info = EwfImgInfo(ewf_handle)
    scan_report = {
        'image': ewf_path,
        'scanned_at': datetime.utcnow().isoformat() + 'Z',
        'volumes': [],
        'artifacts': []
    }

    # try to read partition table
    try:
        vol = pytsk3.Volume_Info(img_info)
        for part in vol:
            try:
                desc = part.info.desc.decode('utf-8', 'ignore')
            except Exception:
                desc = str(part.info.desc)
            scan_report['volumes'].append({
                'start': part.start,
                'length': part.len,
                'desc': desc,
                'slot': part.addr
            })
            # scan each partition's FS
            artifacts = scan_filesystem(img_info, part)
            for a in artifacts:
                a.update({'partition': part.addr})
                scan_report['artifacts'].append(a)
    except Exception:
        # no partition table or pytsk3 couldn't read it -> attempt to scan as single FS image
        artifacts = scan_filesystem(img_info, type(None))
        for a in artifacts:
            a.update({'partition': None})
            scan_report['artifacts'].append(a)

    img_info.close()
    return scan_report

def pretty_print_report(report):
    rows = []
    for a in report['artifacts']:
        mtime = a.get('mtime')
        mtime_str = datetime.utcfromtimestamp(mtime).isoformat() + 'Z' if (mtime and isinstance(mtime, (int, float))) else ''
        rows.append([a.get('artifact'), a.get('found_path'), a.get('partition'), a.get('size') or '', mtime_str])
    print("\nScan summary for:", report['image'])
    print(tabulate(rows, headers=['ArtifactPattern', 'FoundPath', 'Partition', 'Size', 'MTime'], tablefmt='github'))

if __name__ == '__main__':
    if len(sys.argv) != 2:
        print("Usage: python scan_e01_artifacts.py /path/to/image.E01")
        sys.exit(1)
    ewf_path = sys.argv[1]
    if not os.path.exists(ewf_path):
        print("File not found:", ewf_path); sys.exit(1)

    print("Scanning image (read-only):", ewf_path)
    try:
        report = scan_image(ewf_path)
    except Exception as e:
        print("Error while scanning image:", e)
        sys.exit(1)

    pretty_print_report(report)
    # save JSON
    out = 'scan_results.json'
    with open(out, 'w', encoding='utf-8') as f:
        json.dump(report, f, indent=2, ensure_ascii=False)
    print("\nSaved JSON report to", out)
