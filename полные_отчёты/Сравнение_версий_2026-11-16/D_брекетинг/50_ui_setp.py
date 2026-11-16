# -*- coding: utf-8 -*-
"""D6: поиск имени свойства 0x2B9 через таблицы UI_SETP_* / вхождения u16 0x02B9.

1) Все строки 'UI_SETP' / 'UI_DRIVE' (ASCII) в блоке 1 — адреса.
2) Все вхождения u16 0x02B9 в блоках 0/1 (в т.ч. .rodata) — с контекстом:
   если рядом лежит указатель на строку UI_SETP_*/UI_DRIVE*, получим имя свойства.
"""
import sys, re, struct
sys.path.insert(0, r'<корень проекта>\Анализ_прошивки\Сравнение_версий_2026-11-16\D_брекетинг')
from dhelp import *  # noqa

for model, idx in (('X-H2', 1), ('X-H2', 0)):
    b = load(model, 'new', idx)
    print(f'\n===== {model} new b{idx}')
    for pat in (b'UI_SETP', b'UI_DRIVE'):
        addrs = [b.base + m.start() for m in re.finditer(re.escape(pat), b.data)]
        print(f'  {pat!r}: {len(addrs)} шт., первые: {[hex(a) for a in addrs][:8]}')
        for a in addrs[:6]:
            print('     ', repr(b.cstr(a, 60) or ''))
    # вхождения u16 0x02B9
    occ = []
    pat = b'\xb9\x02'
    start = 0
    while True:
        i = b.data.find(pat, start)
        if i < 0:
            break
        occ.append(b.base + i)
        start = i + 1
    print(f'  u16 0x02B9: {len(occ)} вхождений, первые: {[hex(a) for a in occ][:10]}')
    for a in occ[:6]:
        o = b.off(a)
        seg = b.data[max(0, o - 16):o + 24]
        print(f'    {a:#x}: {seg.hex(" ")}')
