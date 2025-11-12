from pathlib import Path
import os, pandas as pd, re

input_dir  = Path(os.path.expandvars(r"C:\Users\aromi\바탕 화면\langflow\lang_flow\Dataset"))
output_dir = Path(os.path.expandvars(r"C:\Users\aromi\바탕 화면\langflow\lang_flow\data_jsonl"))
output_dir.mkdir(parents=True, exist_ok=True)

print(f"[PATH] input_dir = {input_dir} (exists={input_dir.exists()})")
print(f"[PATH] output_dir = {output_dir} (exists={output_dir.exists()})")

# === ASEP 관련 파일 이름 키워드 목록 (대소문자 무시) ===
asep_keywords = [
    "RegistryASEPs",
    "SoftwareASEPs",
    "SoftwareClassesASEPs",
    "SoftwareWoW6432ASEPs",
    "SystemASEPs",
    "UserClassesASEPs",
]
kw_lower = tuple(k.lower() for k in asep_keywords)

# === CSV 안전 로더 (인코딩 자동 폴백) ===
def safe_read_csv(p: Path):
    for enc in ("utf-8-sig", "utf-8", "cp949", "euc-kr"):
        try:
            return pd.read_csv(p, dtype=str, encoding=enc).fillna("")
        except Exception as e:
            last_err = e
    raise last_err

def add_persistence_tag(p: Path):
    print(f"[LOAD] {p}")
    df = safe_read_csv(p)
    df["tag"] = "Persistence"

    out_name = re.sub(r"\.csv$", "_tagged.csv", p.name, flags=re.I)
    out_path = output_dir / out_name
    df.to_csv(out_path, index=False, encoding="utf-8-sig")
    print(f"[SAVE] -> {out_path}")

# === 실행: 재귀 검색 + 필터 현황 출력 ===
all_csv = [p for p in input_dir.rglob("*.csv")]
print(f"[SCAN] CSV files found: {len(all_csv)}")

targets = [p for p in all_csv if any(k in p.name.lower() for k in kw_lower)]
print(f"[SCAN] ASEP-matched files: {len(targets)}")
for p in targets:
    print(f"  - {p}")

if not input_dir.exists():
    print("[ERR] input_dir가 존재하지 않습니다 (볼륨 마운트 확인).")
elif not all_csv:
    print("[WARN] CSV 파일이 없습니다.")
elif not targets:
    print("[WARN] CSV는 있으나 ASEP 키워드에 매칭된 파일이 없습니다. asep_keywords 또는 파일명 확인.")
else:
    for p in targets:
        try:
            add_persistence_tag(p)
        except Exception as e:
            print(f"[FAIL] {p.name}: {e}")
