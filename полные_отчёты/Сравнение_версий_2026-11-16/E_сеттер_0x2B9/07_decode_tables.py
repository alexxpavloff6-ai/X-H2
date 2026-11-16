# -*- coding: utf-8 -*-
"""E7: декодировать огромные switch-таблицы блока 0 (u32 offset/4 от базы adr)
и найти, какие id ведут в чанки района 0x128c300..0x128c800 (в частности 0x128c558).
"""
import sys, re, struct
sys.path.insert(0, r'<корень проекта>\Анализ_прошивки\Сравнение_версий_2026-11-16\E_сеттер_0x2B9')
from ecommon import *  # noqa

MODEL, STATE = 'X-H2', 'new'
b = load(MODEL, STATE, 0)
print(b, 'end', hex(b.end))

TABLES = [
    # (имя, адрес таблицы, база adr, count, first_id, сайт br)
    ('setter? 0x11e6c44', 0x1742000 + 0x89c, 0x11e6c44, 0xd69, 1, 0x11e6c40),
    ('other 0x12aa7dc', 0x1745000 + 0xe70, 0x12aa7dc, 0xd69, 1, 0x12aa7d8),
]

for name, tab, base, cnt, first_id, brsite in TABLES:
    print(f'\n=== {name}: таблица {tab:#x}, база {base:#x}, {cnt} записей ===')
    inrange = []
    bad = 0
    for i in range(cnt):
        v = u32(b, tab + 4 * i)
        sv = v - (1 << 32) if v & 0x80000000 else v
        t = base + sv * 4
        if 0x128c300 <= t < 0x128c800:
            inrange.append((i + first_id, t))
    print('попаданий в район чанков:', len(inrange))
    for idv, t in inrange[:20]:
        print(f'  id/код {idv:#x} -> {t:#x}')
