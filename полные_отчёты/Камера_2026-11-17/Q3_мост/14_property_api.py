# -*- coding: utf-8 -*-
"""Q3 шаг 14: property set/get API и построитель параметров 0x113D9E0."""
import json
import sys
from pathlib import Path

HERE = Path(__file__).resolve().parent
sys.path.insert(0, str(HERE))
from q3common import load, dis, bl_callers, func_start  # noqa: E402

b0 = load('X-H2', 'old', 0)
out = []
for name, va, n in (('set API 0x11335C4', 0x11335C4, 60),
                    ('get API 0x1135930', 0x1135930, 50),
                    ('get API 0x11335EC', 0x11335EC, 40)):
    out.append(f'===== block0 {name} =====')
    out.append(dis(b0, va, n))
    out.append('')

# вызовы построителя 0x113D9E0
callers = []
for idx in (0, 1):
    b = load('X-H2', 'old', idx)
    for s, k in bl_callers(b, 0x113D9E0):
        callers.append({'block': idx, 'site': hex(s), 'func': hex(func_start(b, s) or 0)})
out.append('===== вызовы 0x113D9E0 =====')
for c in callers:
    out.append(str(c))

text = '\n'.join(out)
(HERE / 'property_api.txt').write_text(text + '\n', encoding='utf-8')
(HERE / 'построитель_вызовы.json').write_text(json.dumps(callers, ensure_ascii=False, indent=2) + '\n', encoding='utf-8')
print(text[:9000])
print('вызовы 0x113D9E0:', callers)
