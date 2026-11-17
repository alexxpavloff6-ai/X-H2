# -*- coding: utf-8 -*-
"""Q3 2-й круг, шаг 30: построитель параметров 0x2FE38E4 (src1, флаг = out+0x64).
Ищем запись [x0,#0x64] и условия (CH/ES/выдержка/REC_VIEW)."""
import json
import sys
from pathlib import Path

HERE = Path(__file__).resolve().parent
sys.path.insert(0, str(HERE))
from q3common import load, dis, insns, bl_callers, func_start  # noqa: E402

b1 = load('X-H2', 'old', 1)
fs = func_start(b1, 0x2FE38E4)
print('func_start(0x2FE38E4) =', hex(fs or 0))
out = []
full = dis(b1, 0x2FE38E4, 400)
out.append('===== block1 0x2FE38E4 (построитель src1) =====')
out.append(full)
out.append('')
lines = full.split('\n')
# ищем записи по смещению 0x64 и чтения свойств сценария
idx64 = [i for i, ln in enumerate(lines) if '#0x64]' in ln]
out.append('=== строки с [#0x64] ===')
for i in idx64:
    for j in range(max(0, i - 8), min(len(lines), i + 2)):
        out.append(('>> ' if j == i else '   ') + lines[j])
    out.append('')
callers = []
for idx in (0, 1):
    b = load('X-H2', 'old', idx)
    for s, k in bl_callers(b, 0x2FE38E4):
        callers.append({'block': idx, 'site': hex(s), 'func': hex(func_start(b, s) or 0)})
out.append('=== вызовы 0x2FE38E4 ===')
for c in callers:
    out.append(str(c))
text = '\n'.join(out)
(HERE / '2круг_построитель_параметров.txt').write_text(text + '\n', encoding='utf-8')
(HERE / '2круг_построитель_параметров_вызовы.json').write_text(json.dumps(callers, ensure_ascii=False, indent=2) + '\n', encoding='utf-8')
print('\n'.join(out[out.index('=== строки с [#0x64] ==='):]))
print('вызовы:', callers)
