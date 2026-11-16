# -*- coding: utf-8 -*-
"""E19: поиск таблиц {u64 --> строка, u64 индекс} в блоках 0/1 и вывод строк для
индексов 0x1d..0x2d (кандидаты в имена кодов режима/пункта меню)."""
import sys, re, struct
sys.path.insert(0, r'<корень проекта>\Анализ_прошивки\Сравнение_версий_2026-11-16\E_сеттер_0x2B9')
from ecommon import *  # noqa

MODEL, STATE = 'X-H2', 'new'
PRINT = re.compile(rb'^[\x20-\x7e]{3,120}$')
ID_MIN, ID_MAX = 0x1c, 0x2e

for idx in (0, 1):
    b = load(MODEL, STATE, idx)
    print(f'\n######## блок {idx} {b} ########')
    found = {}
    n = len(b.data)
    for o in range(0, n - 16, 8):
        p = struct.unpack_from('<Q', b.data, o)[0]
        if not (b.base <= p < b.end):
            continue
        s = b.cstr(p)
        if not s or not PRINT.match(s.encode('latin1')):
            continue
        q = struct.unpack_from('<Q', b.data, o + 8)[0]
        if ID_MIN <= q <= ID_MAX:
            found.setdefault(q, []).append((b.base + o, s))
    for k in sorted(found):
        print(f'\n-- индекс {k:#x} ({k}) --')
        for a, s in found[k][:12]:
            print(f'   {a:#x}: {s!r}')
