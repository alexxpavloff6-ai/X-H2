# -*- coding: utf-8 -*-
"""D2: кто читает/пишет параметр blob[0xa8] и кто проверяет его бит 7.

Идея: 0xa8 — байт в blob; в коде он грузится как `mov w0,#0xa8; bl <get_u8>`,
а пишется, вероятно, через сеттер (функции рядом с 0x1492040 / 0x14924b0).
Скрипт находит все `mov w0,#0xa8` в блоке 1 (word-префильтр) и печатает контекст,
а также все проверки `tbnz/tbz/tst ... #0x80` сразу после такого чтения.
"""
import sys, re, struct, json
sys.path.insert(0, r'<корень проекта>\Анализ_прошивки\Сравнение_версий_2026-11-16\D_брекетинг')
from dhelp import *  # noqa

MOV_A8_W0 = 0x52800000 | (0xa8 << 5)     # mov w0,#0xa8
MOV_A8_W1 = 0x52800000 | (0xa8 << 5) | 1  # mov w1,#0xa8

def scan(model, state, idx=1):
    b = load(model, state, idx)
    d = b.data
    rows = []
    for o in range(0, len(d) - 8, 4):
        w0 = struct.unpack_from('<I', d, o)[0]
        if w0 not in (MOV_A8_W0, MOV_A8_W1):
            continue
        w1 = struct.unpack_from('<I', d, o + 4)[0]
        if (w1 & 0xfc000000) != 0x94000000:
            continue
        tgt = b.base + o + 4 + ((w1 & 0x3ffffff) - (1 << 26) if (w1 & 0x2000000) else (w1 & 0x3ffffff)) * 4
        rows.append((b.base + o, tgt))
    return b, rows

for model, state in (('X-H2', 'new'), ('X-H2', 'old')):
    b, rows = scan(model, state)
    print(f'\n===== {model} {state}: {len(rows)} мест mov w0/w1,#0xa8 + bl')
    for va, tgt in rows:
        ins = insns(b, va, 6)
        after = insns(b, va + 12, 6)
        ctx = ' | '.join(f'{x.mnemonic} {x.op_str}' for x in ins[:4])
        chk = [f'{x.mnemonic} {x.op_str}' for x in after
               if x.mnemonic in ('tbnz', 'tbz', 'tst', 'and', 'ubfx', 'sxtb', 'cbnz', 'cbz', 'cmp')]
        print(f'  {va:#x} -> bl {tgt:#x}: {ctx}')
        if chk:
            print(f'        после: {chk[:4]}')
