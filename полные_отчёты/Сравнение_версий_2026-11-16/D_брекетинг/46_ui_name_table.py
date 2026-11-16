# -*- coding: utf-8 -*-
"""D5: таблица «id свойства → UI-имя». Ищем ссылки на строки UI_MENUCOM_ITEM_*
и проверяем, не стоит ли рядом id 0x02B9 (наше свойство).

Строки: DRIVE_MODE 0x31aeb48, BRACKET 0x31ae9d0, MULTI_EXPO 0x31ae9e8,
ISO_BKT 0x31aed20, CLARITY 0x31ae958 (X-H2 5.33, блок 1).
Ищем 8-байтовые указатели на них (или на смежные строки) и печатаем окрестность,
включая возможные u16-коды.
"""
import sys, re, struct
sys.path.insert(0, r'<корень проекта>\Анализ_прошивки\Сравнение_версий_2026-11-16\D_брекетинг')
from dhelp import *  # noqa

b = load('X-H2', 'new', 1)
d = b.data
TARGETS = {
    'DRIVE_MODE': 0x31aeb48, 'BRACKET': 0x31ae9d0, 'MULTI_EXPO': 0x31ae9e8,
    'ISO_BKT': 0x31aed20, 'CLARITY': 0x31ae958, 'PRE_SHOOT': 0x31aeb88,
    'SELFTIMER': 0x31aeba8,
}
for name, va in TARGETS.items():
    pat = struct.pack('<Q', va)
    hits = find_bytes(b, pat)
    print(f'\n{name} {va:#x}: ссылок(8B) {len(hits)}: {[hex(h) for h in hits][:6]}')
    for h in hits[:3]:
        print('   контекст:', d[b.off(h) - 32:b.off(h) + 40].hex(' '))
        # ищем 0x02b9 в окне ±0x40
        seg = d[b.off(h) - 0x40:b.off(h) + 0x40]
        pos = seg.find(b'\xb9\x02')
        if pos >= 0:
            print('   рядом найден u16 0x02b9 по смещению', hex(pos - 0x40))
    # 4-байтовые ссылки (если таблица 32-битная)
    pat4 = struct.pack('<I', va)
    h4 = find_bytes(b, pat4)
    if h4:
        print(f'   ссылок(4B): {[hex(h) for h in h4][:6]}')
