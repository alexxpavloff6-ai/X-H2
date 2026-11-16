# -*- coding: utf-8 -*-
"""(1) Проверка configuration-чанка из settings.generated.json на наших DAT.
(2) Сводка progress/xt5/4.31/progress.generated.json (что у fujimod снято, что «stale»)."""
import hashlib, json, os, sys
sys.stdout.reconfigure(encoding="utf-8")

ROOT = r"<корень проекта>"
CAT = os.path.join(ROOT, r"Внешние_репозитории\fujimod\catalog")
DAT = {"xh2": r"FIRMWARE\ver 5.30\FWUP0028.DAT",
       "xh2s": r"Firmware на прочиеFuji\FWUP0027.DAT",
       "xt5": r"Firmware на прочиеFuji\FWUP0030.DAT"}
VER = {"xh2": "5.30", "xh2s": "7.30", "xt5": "4.31"}

print("== settings.configuration = флеш-образ (DAT[628:] xor FF) ==")
for cam in ("xh2", "xh2s", "xt5"):
    p = os.path.join(CAT, "firmware", cam, VER[cam], "settings.generated.json")
    if not os.path.exists(p):
        print("  %-5s нет settings.generated.json" % cam)
        continue
    st = json.load(open(p, encoding="utf-8"))
    c = st["configuration"]
    d = open(os.path.join(ROOT, DAT[cam]), "rb").read()
    dec = bytes(b ^ 0xFF for b in d[628:])
    got = hashlib.sha256(dec[c["flash_offset"]:c["flash_offset"] + c["bytes"]]).hexdigest()
    print("  %-5s flash_offset=0x%-6X bytes=%-7d sha совпал=%s  defaults=%s sections=%d" % (
        cam, c["flash_offset"], c["bytes"], got == c["sha256"], st["defaults"], len(st["sections"])))

print("\n== progress/xt5/4.31 ==")
pr = json.load(open(os.path.join(CAT, r"progress\xt5\4.31\progress.generated.json"), encoding="utf-8"))
print("  facts located %s / %s; schema=%s" % (pr["facts"]["located"], pr["facts"]["total"], pr["schema"]))
for t in pr["tracks"]:
    print("  трек %-12s phase=%-10s weight=%s cells=%s" % (t["id"], t.get("phase"), t.get("weight"), t.get("cells")))
    for s in t["stages"]:
        print("     %-22s %-10s %s" % (s["id"], s["result"], s["title"]))
    for k in t:
        if k not in ("id", "title", "phase", "weight", "cells", "stages"):
            print("     + %s = %s" % (k, json.dumps(t[k], ensure_ascii=False)[:300]))
