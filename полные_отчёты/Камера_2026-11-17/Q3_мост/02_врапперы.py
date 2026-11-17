# -*- coding: utf-8 -*-
"""Q3 шаг 2: три враппера диспетчера 0x4A458 и контекст точки входа в блоке 2."""
import json
import sys
from pathlib import Path

HERE = Path(__file__).resolve().parent
sys.path.insert(0, str(HERE.parents[1] / 'Сравнение_версий_2026-11-16'))
from fwcommon import load, dis, bl_callers, func_start  # noqa: E402

b0 = load('X-H2', 'old', 0)
b2 = load('X-H2', 'old', 2)

out = []
out.append('=== block0: функция 0x14CE590 (вызов диспетчера в 0x14CE5D4) ===')
out.append(dis(b0, 0x14CE500, 96))
out.append('')
out.append('=== block0: функция 0x14D1214 (вызов диспетчера в 0x14D1238) ===')
out.append(dis(b0, 0x14D1180, 128))
out.append('')
out.append('=== block2: контекст 0x4A380..0x4A498 (точка входа 0x4A458) ===')
out.append(dis(b2, 0x4A380, 70))
out.append('')
out.append('=== block2: функция 0x35E78 ===')
out.append(dis(b2, 0x35E78, 60))
out.append('')
out.append('=== block2: функция 0x5544C ===')
out.append(dis(b2, 0x5544C, 60))

callers = {}
for name, target in (('wrap_14CE590', 0x14CE590), ('wrap_14CF45C', 0x14CF45C),
                     ('wrap_14D1214', 0x14D1214), ('getter_14CF354', 0x14CF354),
                     ('scalar_14CF404', 0x14CF404)):
    rows = []
    for idx in (0, 1, 2):
        b = load('X-H2', 'old', idx)
        for s, k in bl_callers(b, target):
            rows.append({'block': idx, 'site': hex(s), 'kind': k, 'func': hex(func_start(b, s) or 0)})
    callers[name] = rows

text = '\n'.join(out)
(HERE / 'врапперы.txt').write_text(text + '\n', encoding='utf-8')
(HERE / 'врапперы_вызовы.json').write_text(json.dumps(callers, ensure_ascii=False, indent=2) + '\n', encoding='utf-8')
print(text)
print('=== вызовы врапперов ===')
for k, v in callers.items():
    print(k, len(v))
    for row in v[:60]:
        print('  ', row)
