#!/usr/bin/env python3
# -*- coding: utf-8 -*-
import subprocess
from pathlib import Path
from typing import List

MODULE_NAME="LECmd"; MODULE_BIN_DIR=Path(r"D:\KAPE\Modules\bin")

def _find_exe(exe:str)->bool:
    for p in MODULE_BIN_DIR.rglob("*.exe"):
        if p.name.lower()==exe.lower(): return True
    return False

def _cands(base_out:Path,dl:str)->list[Path]:
    return [base_out/f"$NFTS_{dl[0]}"/"Artifacts", base_out/dl[0]/"Artifacts"]

def _loc(base_out:Path,dl:str)->Path|None:
    for p in _cands(base_out,dl):
        if p.exists(): return p
    return None

def _out_root(artifacts:Path)->Path: return artifacts.parent

def _stream(cmd:list[str],log:Path,timeout:int)->int:
    log.parent.mkdir(parents=True,exist_ok=True)
    with open(log,"w",encoding="utf-8") as lf:
        lf.write("[CMD] "+" ".join(cmd)+"\n")
        proc=subprocess.Popen(cmd,stdout=subprocess.PIPE,stderr=subprocess.STDOUT,text=True); assert proc.stdout
        try:
            for line in proc.stdout: lf.write(line.rstrip()+"\n")
            return proc.wait(timeout=timeout if timeout>0 else None)
        except subprocess.TimeoutExpired:
            proc.kill(); lf.write("[ERROR] timeout\n"); return -9

def run(drive_letters:List[str],unmount_callback,cfg:dict)->bool:
    BASE_OUT:Path=cfg["BASE_OUT"]; KAPE_EXE:Path=cfg["KAPE_EXE"]; TO=int(cfg.get("PROC_TIMEOUT_SEC",1800))
    if not _find_exe("LECmd.exe"): print("[SKIP] LECmd: exe not found"); return False
    for dl in drive_letters:
        art=_loc(BASE_OUT,dl)
        if not art: print(f"[SKIP] {dl} LECmd: Artifacts missing"); continue
        root=_out_root(art); mdest=root/MODULE_NAME; log=root/"Logs"/f"{MODULE_NAME}.log"
        cmd=[str(KAPE_EXE),"--msource",str(art),"--mdest",str(mdest),"--module",MODULE_NAME,"--mef","csv","--vss","false"]
        print(f"[RUN ] {dl} {MODULE_NAME}"); rc=_stream(cmd,log,TO)
        if rc!=0:
            print(f"[FAIL] {dl} {MODULE_NAME} rc={rc}")
            try:
                if mdest.exists() and not any(mdest.iterdir()): mdest.rmdir()
            except Exception: pass
        else: print(f"[OK  ] {dl} {MODULE_NAME}")
    return False
