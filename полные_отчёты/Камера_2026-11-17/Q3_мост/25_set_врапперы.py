# -*- coding: utf-8 -*-
"""Q3 2-й круг, шаг 25: block0 set-врапперы и их вызывающие; update-вход 0x4C148;
поиск id=0x4C среди вызовов set-врапперов."""
import json
import re
import sys
from pathlib import Path

HERE = Path(__file__).resolve().parent
sys.path.insert(0, str(HERE))
from q3common import loader, load, dis, bl_callers, insns, func_start  # noqa: E402

L = loader()
b0 = load('X-H2', 'old', 0)
b1 = load('X-H2', 'old', 1)
out = []

# дизасм block0 set-врапперов
for name, va, n in (('block0 set-wrap 0x14CEDAC', 0x14CEDAC, 40),
                    ('block0 set-wrap 0x14D098C', 0x14D098C, 30),
                    ('block0 set-wrap 0x14D0A08', 0x14D0A08, 30),
                    ('loader update 0x4C148', 0x4C148, 120)):
    b = L if va < 0x100000 else b0
    out.append(f'===== {name} =====')
    out.append(dis(b, va, n))
    out.append('')

# вызывающие set-врапперов и update-входа
wrappers = {'wrap_0x14CEDAC': 0x14CEDAC, 'wrap_0x14D098C': 0x14D098C,
            'wrap_0x14D0A08': 0x14D0A08, 'loader_update_0x4C148': 0x4C148,
            'loader_create_0x4BC90': 0x4BC90}
callers = {}
for name, tgt in wrappers.items():
    rows = []
    for src_name, b in (('block0', b0), ('block1', b1), ('loader', L)):
        for s, k in bl_callers(b, tgt):
            # ищем id в w0 в preceding 8 инструкциях
            idval = None
            for ins in insns(b, s - 0x20, 9):
                m = re.fullmatch(r'mov(z)? w0, #(0x[0-9a-f]+|\d+)', ins.mnemonic + ' ' + ins.op_str)
                if m:
                    idval = int(m.group(2), 0)
            rows.append({'src': src_name, 'site': hex(s), 'func': hex(func_start(b, s) or 0), 'w0_id': hex(idval) if idval is not None else None})
    callers[name] = rows

out.append('=== вызывающие set-врапперов (с id в w0) ===')
for name, rows in callers.items():
    out.append(f'--- {name}: {len(rows)} ---')
    for r in rows:
        mark = '  <<< id=0x4C' if r['w0_id'] == '0x4c' else ''
        out.append(f"  {r['src']} {r['site']} func={r['func']} w0={r['w0_id']}{mark}")
    out.append('')

text = '\n'.join(out)
(HERE / '2круг_set_врапперы.txt').write_text(text + '\n', encoding='utf-8')
(HERE / '2круг_set_врапперы_вызовы.json').write_text(json.dumps(callers, ensure_ascii=False, indent=2) + '\n', encoding='utf-8')
# печать только вызывающих + краткий дизасм врапперов
print('\n'.join(out[out.index('=== вызывающие set-врапперов (с id в w0) ==='):]))
print('=== block0 set-wrap 0x14CEDAC ===')
print(dis(b0, 0x14CEDAC, 30))
