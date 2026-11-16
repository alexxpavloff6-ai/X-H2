# -*- coding: utf-8 -*-
"""D7: отправитель события 0x358 и пространства имён «код события» vs «id свойства».

1) Все `mov w0,#0x358` (movz) в блоках 0/1/2 X-H2 5.33 — с контекстом (±6 инструкций)
   и указанием, куда идёт bl (отправка события 0x2c116ac / get/set свойства блока 0).
2) Дизассемблер 0x2c116ac (функция отправки события).
3) Контекст функции 0x2b478b0 (начало, вызывающие, строки).
"""
import sys, re, struct
sys.path.insert(0, r'<корень проекта>\Анализ_прошивки\Сравнение_версий_2026-11-16\D_брекетинг')
from dhelp import *  # noqa

M358 = 0x52800000 | (0x358 << 5)      # mov w0,#0x358
M358W1 = M358 | 1                     # mov w1,#0x358

for idx in (0, 1, 2):
    b = load('X-H2', 'new', idx)
    d = b.data
    rows = []
    for o in range(0, len(d) - 4, 4):
        w = struct.unpack_from('<I', d, o)[0]
        if w in (M358, M358W1):
            rows.append(b.base + o)
    print(f'\n===== b{idx}: mov w0/w1,#0x358: {len(rows)} мест')
    for va in rows:
        xs = insns(b, va, 4)
        nxt = ' | '.join(f'{y.mnemonic} {y.op_str}' for y in xs[1:3])
        print(f'  {va:#x}: {xs[0].mnemonic} {xs[0].op_str}   -> {nxt}')

print('\n=== 0x2c116ac ===')
b1 = load('X-H2', 'new', 1)
print(dis(b1, 0x2c116ac, 40))

print('\n=== 0x2b478b0 контекст ===')
print(dis(b1, 0x2b47880, 40))
print('callers 0x2b478b0:', [hex(a) for a, _ in bl_callers(b1, 0x2b478b0)])
