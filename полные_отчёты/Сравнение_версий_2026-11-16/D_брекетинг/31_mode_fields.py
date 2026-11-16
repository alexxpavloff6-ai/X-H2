# -*- coding: utf-8 -*-
"""D2: откуда берутся режим кадра [struct+0x3978] и счётчик [struct+0x429c].

В функции 0x2dd1bb0 (X-H2) перед многокадровым циклом:
    2dd1f94: ldr w0,[x19,#0x3978] ; w28 = 1 ; cmp w0,#0x2c ; b.eq multi
    2dd216c: ldrh w0,[x19+0x429c] ; w28 = 2/3/4 по значению 2/3/...
То есть многокадровый путь включается кодом режима 0x2C и счётчиком из +0x429c.
Скрипт ищет все обращения к этим смещениям и места, где пишется 0x2C/2/3.
"""
import sys, re, struct
sys.path.insert(0, r'<корень проекта>\Анализ_прошивки\Сравнение_версий_2026-11-16\D_брекетинг')
from dhelp import *  # noqa

OFFS = (0x3978, 0x429c)

for model, state in (('X-H2', 'new'), ('X-H2', 'old')):
    b = load(model, state, 1)
    hist = []
    rows = []
    for x in all_insns(b):
        if x.mnemonic == '.byte':
            continue
        if x.mnemonic in ('ldr', 'str', 'ldrh', 'strh', 'ldrb', 'strb', 'ldrsh', 'ldrsw'):
            for off in OFFS:
                if re.search(r'\[x\d+, #0x%x\]' % off, x.op_str):
                    rows.append((x.address, f'{x.mnemonic} {x.op_str}', list(hist[-3:])))
        hist.append(x)
        if len(hist) > 8:
            hist.pop(0)
    print(f'\n===== {model} {state}: обращения к {[hex(o) for o in OFFS]}: {len(rows)}')
    for a, s, ctx in rows:
        print(f'  {a:#x}: {s}   <- ' + ' | '.join(f'{c.mnemonic} {c.op_str}' for c in ctx))

# отдельно: где в код грузится константа 0x2c и рядом есть 0x3978 / 0x429c
print('\n--- контекст записей режима (ищем str ... , #0x3978) с константами ---')
b = load('X-H2', 'new', 1)
for x in all_insns(b):
    if x.mnemonic == '.byte':
        continue
    if re.search(r'\[x\d+, #0x3978\]', x.op_str) and x.mnemonic.startswith('str'):
        print(dis(b, x.address - 0x20, 12))
        print('---')
