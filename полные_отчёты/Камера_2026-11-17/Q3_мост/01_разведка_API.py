# -*- coding: utf-8 -*-
"""Q3 шаг 1: семейство record-API в блоке 0 (5.30) и диспетчер 0x4A458 в блоке 2.

Ищем set-аналог геттера 0x14CF354: функции рядом, которые строят запрос
с другим типом (не 2) и вызывают 0x4A458. Только чтение блоков.
"""
import json
import sys
from pathlib import Path

HERE = Path(__file__).resolve().parent
sys.path.insert(0, str(HERE.parents[1] / 'Сравнение_версий_2026-11-16'))
from fwcommon import load, dis, insns, bl_callers, func_start  # noqa: E402

b0 = load('X-H2', 'old', 0)
b2 = load('X-H2', 'old', 2)

out = []
out.append('=== block0: регион record-API 0x14CF300..0x14CF700 ===')
out.append(dis(b0, 0x14CF300, 256))
out.append('')
out.append('=== block2: диспетчер 0x4A458 (200 инструкций) ===')
out.append(dis(b2, 0x4A458, 200))

# все прямые вызовы диспетчера 0x4A458 из блоков 0..2
callers = {}
for idx in (0, 1, 2):
    b = load('X-H2', 'old', idx)
    callers[f'block{idx}'] = [{'site': hex(s), 'kind': k, 'func': hex(func_start(b, s) or 0)}
                              for s, k in bl_callers(b, 0x4A458)]

text = '\n'.join(out)
(HERE / 'разведка_API.txt').write_text(text + '\n', encoding='utf-8')
(HERE / 'диспетчер_вызовы.json').write_text(json.dumps(callers, ensure_ascii=False, indent=2) + '\n', encoding='utf-8')
print(text[:6000])
print('...')
print('вызовы 0x4A458:', {k: len(v) for k, v in callers.items()})
for k, v in callers.items():
    for row in v[:40]:
        print(k, row)
