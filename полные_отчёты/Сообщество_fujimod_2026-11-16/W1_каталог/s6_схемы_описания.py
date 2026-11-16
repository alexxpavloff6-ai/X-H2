# -*- coding: utf-8 -*-
"""Вытаскивает описания полей из схем каталога fujimod (они порождены из doc-комментариев
Rust-структур, т.е. это официальное объяснение смысла файлов)."""
import json, os, sys
sys.stdout.reconfigure(encoding="utf-8")

SCH = r"<корень проекта>\Внешние_репозитории\fujimod\catalog\schemas"
NAMES = ["settings.generated.schema.json", "state.generated.schema.json", "flash.generated.schema.json",
         "memory-reservations.generated.schema.json", "restart.generated.schema.json",
         "bulk.generated.schema.json", "control-ids.schema.json", "progress.generated.schema.json",
         "ui-setting-names.generated.schema.json", "ui-scene-names.generated.schema.json",
         "firmware-versions.generated.schema.json", "generation.generated.schema.json"]

def walk(node, path="", out=None, depth=0):
    if out is None:
        out = []
    if isinstance(node, dict):
        d = node.get("description")
        title = node.get("title")
        if d or title:
            out.append((path, title, d))
        for k, v in node.items():
            if k in ("description", "title"):
                continue
            walk(v, path + "/" + k if path else k, out, depth + 1)
    elif isinstance(node, list):
        for i, v in enumerate(node):
            walk(v, path + "[%d]" % i, out, depth + 1)
    return out

for n in NAMES:
    p = os.path.join(SCH, n)
    if not os.path.exists(p):
        print("НЕТ:", n)
        continue
    j = json.load(open(p, encoding="utf-8"))
    print("=" * 78)
    print(n, "| title:", j.get("title"))
    for path, title, d in walk(j):
        # только верхние 2 уровня и осмысленные описания
        if d and path.count("/") <= 2:
            print("  %-42s %s" % (path, d[:400]))
