# -*- coding: utf-8 -*-
"""E3: структура района 0x128c400..0x128c700; ссылки на «чанки» как u64 (таблица
дескрипторов свойств {id, setter,...}), и что такое 0x11e6cb4.
"""
import sys, re, struct
sys.path.insert(0, r'<корень проекта>\Анализ_прошивки\Сравнение_версий_2026-11-16\E_сеттер_0x2B9')
from ecommon import *  # noqa

MODEL, STATE = 'X-H2', 'new'
b = load(MODEL, STATE, 0)

print('=== 0x128c380..0x128c520 ===')
dump_range(b, 0x128c380, 0x128c520)

print('\n=== что такое 0x11e6cb4 ===')
dump_range(b, 0x11e6c80, 0x11e6d00)
print('callers of 0x11e6cb4:', [hex(a) for a, k in bl_callers(b, 0x11e6cb4)][:20], '...')

# ищем u64-ссылки на чанки 0x128c558 (начало блока 0x2B9?) и 0x128c648
for tgt in (0x128c518, 0x128c558, 0x128c648, 0x128c4e8, 0x128c6c8, 0x128c5e0):
    hits = find_bytes(b, struct.pack('<Q', tgt))
    print(f'\nu64 refs на {tgt:#x}: {len(hits)} {[hex(h) for h in hits][:12]}')
    for h in hits[:3]:
        o = b.off(h)
        print(f'  {h:#x}: {b.data[max(0,o-32):o+16].hex(" ")}')
