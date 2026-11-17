# -*- coding: utf-8 -*-
"""Q3 2-й круг, шаг 26: построитель записи 0x4C block1 0x311B7C4 (вызывает set id=0x4C).
Ищем источник поля payload+0x64 (флаг)."""
import json
import sys
from pathlib import Path

HERE = Path(__file__).resolve().parent
sys.path.insert(0, str(HERE))
from q3common import load, dis, bl_callers, func_start  # noqa: E402

b1 = load('X-H2', 'old', 1)
out = []
out.append('===== block1 0x311B7C4 (построитель записи 0x4C) =====')
out.append(dis(b1, 0x311B7C4, 160))
out.append('')
# вызывающие 0x311B7C4
callers = []
for idx in (0, 1):
    b = load('X-H2', 'old', idx)
    for s, k in bl_callers(b, 0x311B7C4):
        callers.append({'block': idx, 'site': hex(s), 'func': hex(func_start(b, s) or 0)})
out.append('=== вызовы 0x311B7C4 ===')
for c in callers:
    out.append(str(c))
text = '\n'.join(out)
(HERE / '2круг_построитель_0x4C.txt').write_text(text + '\n', encoding='utf-8')
(HERE / '2круг_построитель_вызовы.json').write_text(json.dumps(callers, ensure_ascii=False, indent=2) + '\n', encoding='utf-8')
print(text[:12000])
