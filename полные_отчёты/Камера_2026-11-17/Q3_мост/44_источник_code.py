# -*- coding: utf-8 -*-
"""Q3 4-й круг, шаг 44: трассировка отображения выдержка->code source[0x5A8].
Вызывающие диспетчера 0x14F72C0 (источник x20), писатели source[0x5A8]."""
import json
import sys
from pathlib import Path

HERE = Path(__file__).resolve().parent
sys.path.insert(0, str(HERE))
from q3common import load, dis, bl_callers, func_start, insns  # noqa: E402

b0 = load('X-H2', 'old', 0)
b1 = load('X-H2', 'old', 1)
out = []
callers = {}
for name, tgt in (('dispatch_0x14F72C0', 0x14F72C0),):
    rows = []
    for idx, b in ((0, b0), (1, b1)):
        for s, k in bl_callers(b, tgt):
            rows.append({'block': idx, 'site': hex(s), 'func': hex(func_start(b, s) or 0)})
    callers[name] = rows
    out.append(f'=== вызовы {name}: {len(rows)} ===')
    for r in rows:
        out.append(f"  block{r['block']} {r['site']} func={r['func']}")
    out.append('')
# контекст вызовов (что такое x20/source)
for r in callers['dispatch_0x14F72C0'][:6]:
    b = b0 if r['block'] == 0 else b1
    site = int(r['site'], 16)
    out.append(f"===== контекст вызова dispatch @ {r['site']} (func {r['func']}) =====")
    out.append(dis(b, site - 0x40, 18))
    out.append('')
text = '\n'.join(out)
(HERE / '4круг_источник_code.txt').write_text(text + '\n', encoding='utf-8')
(HERE / '4круг_dispatch_вызовы.json').write_text(json.dumps(callers, ensure_ascii=False, indent=2) + '\n', encoding='utf-8')
print(text[:10000])
