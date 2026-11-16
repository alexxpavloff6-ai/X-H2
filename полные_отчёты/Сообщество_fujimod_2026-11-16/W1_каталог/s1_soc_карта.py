# -*- coding: utf-8 -*-
"""Сводка catalog/soc/xp5/soc.json: регионы, блоки MMIO, прерывания.
Только чтение клона fujimod; вывод — в stdout и s1_soc_карта.txt."""
import json, os

SOC = r"<корень проекта>\Внешние_репозитории\fujimod\catalog\soc\xp5\soc.json"
OUT = os.path.join(os.path.dirname(os.path.abspath(__file__)), "s1_soc_карта.txt")

j = json.load(open(SOC, encoding="utf-8"))
lines = []
def w(s=""):
    lines.append(s)

w("id=%s architecture=%s schema=%s" % (j.get("id"), j.get("architecture"), j.get("schema")))
w("top-level keys: %s" % list(j.keys()))
w()
w("== processors ==")
for p in j.get("processors", []):
    w("  %-8s %-12s regs=%d" % (p["id"], p["model"], len(p.get("registers") or [])))
w()
w("== memory_regions ==")
for r in j.get("memory_regions", []):
    sz = r["size"]
    s = ("%d" % sz["bytes"]) if sz.get("kind") == "bytes" else str(sz.get("kind"))
    w("  %-18s 0x%08X  size=%s  kind=%s" % (r["id"], r["base"], s, r.get("kind")))
w()
w("== blocks (%d) ==" % len(j.get("blocks", [])))
for b in sorted(j.get("blocks", []), key=lambda x: x["base"]):
    w("  %-24s 0x%08X  size=0x%-6X %s" % (b["id"], b["base"], b["size"], b.get("kind")))
w()
for key in ("interrupts", "interrupt_lines", "irqs", "clocks", "clock_domains", "interconnects", "processors_interconnect"):
    if key in j:
        w("== %s ==" % key)
        v = j[key]
        w("  %d записей; первые 3: %s" % (len(v) if hasattr(v, "__len__") else 1, json.dumps(v[:3] if isinstance(v, list) else v, ensure_ascii=False)[:600]))
        w()
# остальные ключи, которые не разобрали
for k in j:
    if k not in ("id", "architecture", "schema", "processors", "memory_regions", "blocks") and k not in ("interrupts", "interrupt_lines", "irqs", "clocks", "clock_domains", "interconnects"):
        w("== прочее: %s ==" % k)
        w("  " + json.dumps(j[k], ensure_ascii=False)[:1200])
        w()

open(OUT, "w", encoding="utf-8").write("\n".join(lines))
print("\n".join(lines))
