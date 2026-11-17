# -*- coding: utf-8 -*-
"""Q3 3-й круг, шаг 38: кодировка входов оценщика. Писатели fieldB (struct+0xD4,
сеттер 0x1561DB8) и fieldA (+0xCC, 0x1561D94); внутренние геттеры затвора."""
import json
import sys
from pathlib import Path

HERE = Path(__file__).resolve().parent
sys.path.insert(0, str(HERE))
from q3common import load, dis, bl_callers, func_start  # noqa: E402

b0 = load('X-H2', 'old', 0)
b1 = load('X-H2', 'old', 1)
out = []
callers = {}
for name, tgt in (('fieldB_setter_0x1561DB8 (+0xD4)', 0x1561DB8),
                  ('fieldA_setter_0x1561D94 (+0xCC)', 0x1561D94),
                  ('fieldD_setter_0x15632F4 (+0x1CC)', 0x15632F4)):
    rows = []
    for idx, b in ((0, b0), (1, b1)):
        for s, k in bl_callers(b, tgt):
            rows.append({'block': idx, 'site': hex(s), 'func': hex(func_start(b, s) or 0)})
    callers[name] = rows
    out.append(f'=== вызовы {name}: {len(rows)} ===')
    for r in rows[:30]:
        out.append(f"  block{r['block']} {r['site']} func={r['func']}")
    out.append('')

# контекст первых вызовов fieldB setter (как вычисляется значение w1)
for r in callers['fieldB_setter_0x1561DB8 (+0xD4)'][:6]:
    b = b0 if r['block'] == 0 else b1
    site = int(r['site'], 16)
    out.append(f"===== контекст fieldB setter @ {r['site']} (func {r['func']}) =====")
    out.append(dis(b, site - 0x40, 18))
    out.append('')

text = '\n'.join(out)
(HERE / '3круг_кодировка_полей.txt').write_text(text + '\n', encoding='utf-8')
(HERE / '3круг_писатели_полей.json').write_text(json.dumps(callers, ensure_ascii=False, indent=2) + '\n', encoding='utf-8')
print(text[:11000])
