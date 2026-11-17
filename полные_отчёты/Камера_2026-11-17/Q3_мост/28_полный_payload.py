# -*- coding: utf-8 -*-
"""Q3 2-й круг, шаг 28: построитель полного payload 0x4C 0x311B6B8.
payload источник sp+0x48 => флаг payload+0x64 = sp+0xAC. Ищем запись [sp,#0xac]."""
import json
import sys
from pathlib import Path

HERE = Path(__file__).resolve().parent
sys.path.insert(0, str(HERE))
from q3common import load, dis, insns, bl_callers, func_start  # noqa: E402

b1 = load('X-H2', 'old', 1)
# найдём границы функции 0x311B6B8 (до следующего пролога/ret после 0x311B788)
out = []
out.append('===== block1 0x311B6B8 (построитель полного payload 0x4C) =====')
full = dis(b1, 0x311B6B8, 300)
out.append(full)
out.append('')
# выделим строки с sp+0xac и ближайшие контексты
lines = full.split('\n')
flag_lines = [i for i, ln in enumerate(lines) if '#0xac]' in ln or '#0xac,' in ln]
out.append('=== строки с [sp,#0xac] (payload+0x64) ===')
for i in flag_lines:
    for j in range(max(0, i - 6), min(len(lines), i + 2)):
        out.append(('>> ' if j == i else '   ') + lines[j])
    out.append('')
# вызывающие 0x311B6B8
callers = []
for idx in (0, 1):
    b = load('X-H2', 'old', idx)
    for s, k in bl_callers(b, 0x311B6B8):
        callers.append({'block': idx, 'site': hex(s), 'func': hex(func_start(b, s) or 0)})
out.append('=== вызовы 0x311B6B8 ===')
for c in callers:
    out.append(str(c))
text = '\n'.join(out)
(HERE / '2круг_полный_payload.txt').write_text(text + '\n', encoding='utf-8')
(HERE / '2круг_полный_payload_вызовы.json').write_text(json.dumps(callers, ensure_ascii=False, indent=2) + '\n', encoding='utf-8')
print('\n'.join(out[out.index('=== строки с [sp,#0xac] (payload+0x64) ==='):]))
print('вызовы:', callers)
