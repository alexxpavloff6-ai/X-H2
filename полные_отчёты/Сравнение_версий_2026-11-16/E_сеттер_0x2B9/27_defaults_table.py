# -*- coding: utf-8 -*-
"""E27: таблица значений по умолчанию для blob-настроек (0x1ac3cb8, записи {u16 id,u8 value,u8 pad}).
Ищем записи с id 0x8000..0x8030 (в частности 0x801c) и значение 0x2c."""
import sys, re, struct
sys.path.insert(0, r'<корень проекта>\Анализ_прошивки\Сравнение_версий_2026-11-16\E_сеттер_0x2B9')
from ecommon import *  # noqa

MODEL, STATE = 'X-H2', 'new'
for idx in (0, 1):
    b = load(MODEL, STATE, idx)
    for tab in (0x1ac3cb8,):
        if not (b.base <= tab < b.end):
            continue
        print(f'\n### блок {idx}: таблица {tab:#x} ###')
        o = b.off(tab)
        n = 0
        rows = []
        while o + 4 <= len(b.data):
            idv, val = struct.unpack_from('<HB', b.data, o)
            if idv >= 0xfffe:
                break
            rows.append((idv, val, b.base + o))
            o += 4
            n += 1
        print('записей:', n, 'терминатор id:', hex(struct.unpack_from('<H', b.data, o)[0]))
        sel = [r for r in rows if 0x7f00 <= r[0] <= 0x8100]
        print('записей с id 0x7f00..0x8100:', len(sel))
        for idv, val, a in sel:
            print(f'   {a:#x}: id {idv:#06x} value {val:#04x}')
        hit = [r for r in rows if r[0] == 0x801c]
        print('id 0x801c:', [(hex(a), hex(v)) for _, v, a in hit])
        # сколько всего значений 0x2c и какие id
        v2c = [r for r in rows if r[1] == 0x2c]
        print(f'значений 0x2c в таблице: {len(v2c)}; первые: ', [(hex(i), hex(a)) for i, _, a in v2c[:20]])
