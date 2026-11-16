# -*- coding: utf-8 -*-
"""E28: идиома «база 0x28000» (add wD,wS,#0x28,lsl#12) — кто читает/пишет
область blob-настроек RECF (id 0x28000..). Печатаем контексты."""
import sys, re, struct
sys.path.insert(0, r'<корень проекта>\Анализ_прошивки\Сравнение_версий_2026-11-16\E_сеттер_0x2B9')
from ecommon import *  # noqa

for idx in (0, 1):
    b = load('X-H2', 'new', idx)
    print(f'\n######## блок {idx} ########')
    # add wD, wS, #0x28, lsl #12  -> 0x11000000 | (0x28<<10) | (S<<5) | D ; 32-bit form
    # add xD, xS, #0x28, lsl #12 -> 0x91000000 | ...
    pats = []
    for d in range(32):
        for s in range(32):
            pats.append(0x11000000 | (0x28 << 10) | 0x00400000 | (s << 5) | d)
            pats.append(0x91000000 | (0x28 << 10) | 0x00400000 | (s << 5) | d)
    pats = set(pats)
    hits = []
    for va, w in iter_words(b):
        if w in pats:
            hits.append(va)
    print('найдено идиом «+0x28000»:', len(hits))
    for va in hits[:40]:
        ins = list(insns(b, va, 1))
        print(f'\n--- {va:#x}: {ins[0].mnemonic} {ins[0].op_str}' if ins else f'\n--- {va:#x}')
        for y in all_insns(b, va - 0x20, va + 0x40):
            if y.mnemonic != '.byte':
                print(f'   {y.address:x}: {y.mnemonic:8} {y.op_str}')
