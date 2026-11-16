# -*- coding: utf-8 -*-
"""E10: поиск таблиц {id=0x2B9, value} в данных блоков 0/1 (u16/u32/u64 варианты),
плюс контекст (u16/u32 окно) и ссылки ADRP+ADD на найденные адреса.
"""
import sys, re, struct
sys.path.insert(0, r'<корень проекта>\Анализ_прошивки\Сравнение_версий_2026-11-16\E_сеттер_0x2B9')
from ecommon import *  # noqa

MODEL, STATE = 'X-H2', 'new'

def occurrences(b, val, width):
    pat = struct.pack('<H' if width == 2 else '<I', val)
    out = []
    start = 0
    while True:
        i = b.data.find(pat, start)
        if i < 0:
            break
        out.append(b.base + i)
        start = i + 1
    return out

for idx in (0, 1):
    b = load(MODEL, STATE, idx)
    print(f'\n######## блок {idx} {b} ########')
    for width in (2, 4):
        hits = occurrences(b, 0x2b9, width)
        print(f'\nu{width*8} 0x2b9: {len(hits)} вхождений')
        near2c = []
        for a in hits:
            o = b.off(a)
            win = b.data[o:o + 32]
            # ищем 0x2c в окне как u16 или u8
            vals16 = struct.unpack_from('<16H', b.data, o) if o + 32 <= len(b.data) else ()
            if any(v == 0x2c for v in vals16) or (len(win) > 2 and win[2] == 0x2c):
                near2c.append(a)
        print('  рядом есть 0x2c:', [hex(a) for a in near2c][:20])
        for a in hits[:15]:
            o = b.off(a)
            seg = b.data[max(0, o - 8):o + 24]
            print(f'  {a:#x}: {seg.hex(" ")}')
