# -*- coding: utf-8 -*-
"""Сводка control-ids.generated.json для X-H2S 7.30 / X-T5 4.31."""
import json, sys
sys.stdout.reconfigure(encoding="utf-8")

BASE = r"<корень проекта>\Внешние_репозитории\fujimod\catalog\firmware"
for cam in ("xh2s\\7.30", "xt5\\4.31"):
    p = BASE + "\\" + cam + r"\control-ids.generated.json"
    j = json.load(open(p, encoding="utf-8"))
    print("=====", cam)
    for k, v in j.items():
        if k in ("$schema", "schema"):
            continue
        if isinstance(v, list):
            print("  %-22s list[%d]  %s" % (k, len(v), json.dumps(v[:2], ensure_ascii=False)[:300]))
        elif isinstance(v, dict):
            print("  %-22s dict keys=%s" % (k, list(v)[:15]))
        else:
            print("  %-22s %r" % (k, v))
    # inputs
    inp = j.get("inputs") or {}
    if isinstance(inp, dict):
        print("  inputs: %d; примеры:" % len(inp))
        for name, val in list(inp.items())[:6]:
            print("    %-28s %s" % (name, json.dumps(val, ensure_ascii=False)[:220]))
    print()
