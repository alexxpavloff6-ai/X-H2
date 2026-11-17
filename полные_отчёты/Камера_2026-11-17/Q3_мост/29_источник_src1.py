# -*- coding: utf-8 -*-
"""Q3 2-й круг, шаг 29: вызывающие построителя payload (0x311BA94/0x311BAB0),
источник src1 (x0, 0xA8 байт), поле x0+0x64 = флаг."""
import json
import sys
from pathlib import Path

HERE = Path(__file__).resolve().parent
sys.path.insert(0, str(HERE))
from q3common import load, dis, bl_callers, func_start  # noqa: E402

b1 = load('X-H2', 'old', 1)
out = []
for name, va, n in (('0x311BA94 (wrapper1)', 0x311BA94, 30),
                    ('0x311BAB0 (wrapper2)', 0x311BAB0, 30)):
    out.append(f'===== {name} =====')
    out.append(dis(b1, va, n))
    out.append('')

callers = {}
for name, tgt in (('wrapper1_0x311BA94', 0x311BA94), ('wrapper2_0x311BAB0', 0x311BAB0)):
    rows = []
    for idx in (0, 1):
        b = load('X-H2', 'old', idx)
        for s, k in bl_callers(b, tgt):
            rows.append({'block': idx, 'site': hex(s), 'func': hex(func_start(b, s) or 0)})
    callers[name] = rows
    out.append(f'=== вызовы {name}: {len(rows)} ===')
    for r in rows:
        out.append(str(r))
    out.append('')

# дизасм первого вызывающего контекст (вокруг site)
for name, rows in callers.items():
    for r in rows[:3]:
        b = load('X-H2', 'old', r['block'])
        site = int(r['site'], 16)
        out.append(f"===== контекст вызова {name} @ {r['site']} (func {r['func']}) =====")
        out.append(dis(b, site - 0x50, 22))
        out.append('')

text = '\n'.join(out)
(HERE / '2круг_источник_src1.txt').write_text(text + '\n', encoding='utf-8')
(HERE / '2круг_источник_src1_вызовы.json').write_text(json.dumps(callers, ensure_ascii=False, indent=2) + '\n', encoding='utf-8')
print(text[:11000])
