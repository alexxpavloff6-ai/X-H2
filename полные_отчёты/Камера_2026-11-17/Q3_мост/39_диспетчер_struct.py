# -*- coding: utf-8 -*-
"""Q3 3-й круг, шаг 39: диспетчер заполнения struct 0x14F72C0 (fieldB case),
вызывающие врапперов fieldB 0x154CFE8 / fieldA 0x154CF44."""
import json
import sys
from pathlib import Path

HERE = Path(__file__).resolve().parent
sys.path.insert(0, str(HERE))
from q3common import load, dis, bl_callers, func_start  # noqa: E402

b0 = load('X-H2', 'old', 0)
b1 = load('X-H2', 'old', 1)
out = []
out.append('===== диспетчер 0x14F72C0 (начало, jump-table) =====')
out.append(dis(b0, 0x14F72C0, 70))
out.append('')
callers = {}
for name, tgt in (('fieldB_wrap_0x154CFE8', 0x154CFE8), ('fieldA_wrap_0x154CF44', 0x154CF44)):
    rows = []
    for idx, b in ((0, b0), (1, b1)):
        for s, k in bl_callers(b, tgt):
            rows.append({'block': idx, 'site': hex(s), 'func': hex(func_start(b, s) or 0)})
    callers[name] = rows
    out.append(f'=== вызовы {name}: {len(rows)} ===')
    for r in rows[:20]:
        out.append(f"  block{r['block']} {r['site']} func={r['func']}")
    out.append('')
# контекст вызова fieldB wrapper (значение w1)
for r in callers['fieldB_wrap_0x154CFE8'][:4]:
    b = b0 if r['block'] == 0 else b1
    site = int(r['site'], 16)
    out.append(f"===== контекст fieldB wrap @ {r['site']} =====")
    out.append(dis(b, site - 0x30, 14))
    out.append('')
text = '\n'.join(out)
(HERE / '3круг_диспетчер_struct.txt').write_text(text + '\n', encoding='utf-8')
(HERE / '3круг_врапперы_полей_вызовы.json').write_text(json.dumps(callers, ensure_ascii=False, indent=2) + '\n', encoding='utf-8')
print(text[:11000])
