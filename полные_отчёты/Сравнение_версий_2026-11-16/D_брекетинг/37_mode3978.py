# -*- coding: utf-8 -*-
"""D4: что означает код режима [ctx+0x3978] == 0x2C и счётчик [ctx+0x429c].

Шаг 1: все места, где поле 0x3978 пишется (str/strh, в т.ч. через add x?,x?,#0x3978),
и все места, где оно сравнивается с 0x2C (и соседними значениями).
Печатается контекст ±6 инструкций — по нему видно источник значения и строки режимов.
"""
import sys, re, struct
from collections import deque
sys.path.insert(0, r'<корень проекта>\Анализ_прошивки\Сравнение_версий_2026-11-16\D_брекетинг')
from dhelp import *  # noqa

MODEL, STATE = 'X-H2', 'new'
b = load(MODEL, STATE, 1)
d = b.data

WRITE_OFF = 0x3978
CNT_OFF = 0x429c

def imm_of(x):
    m = re.search(r'#(0x[0-9a-f]+|\d+)', x.op_str)
    return int(m.group(1), 0) if m else None

writes = []       # (addr, text, context)
cmps = []         # (addr, text, context, field_read)
adds = []         # add xN, xM, #0x3978
hist = deque(maxlen=10)
for x in all_insns(b):
    if x.mnemonic == '.byte':
        continue
    txt = f'{x.mnemonic} {x.op_str}'
    # запись по смещению
    if x.mnemonic in ('str', 'strh', 'stur', 'sturh'):
        m = re.search(r'\[(x\d+), #0x%x\]' % WRITE_OFF, x.op_str)
        if m:
            writes.append((x.address, txt, [f'{y.mnemonic} {y.op_str}' for y in hist]))
    # add базы 0x3978
    if x.mnemonic == 'add' and re.search(r'#0x%x$' % WRITE_OFF, x.op_str):
        adds.append((x.address, txt, [f'{y.mnemonic} {y.op_str}' for y in hist]))
    # сравнение с 0x2c / соседними
    if x.mnemonic in ('cmp', 'subs') and imm_of(x) in (0x2a, 0x2b, 0x2c, 0x2d, 0x2e, 0x2f):
        prev = [f'{y.mnemonic} {y.op_str}' for y in hist]
        field_read = any(re.search(r'\[x\d+, #0x3978\]', t) for t in prev[-4:])
        cmps.append((x.address, txt, prev, field_read))
    hist.append(x)

print(f'=== записей в [x, #0x3978]: {len(writes)}')
for a, t, ctx in writes:
    print(f'\n--- {a:#x}: {t}')
    for c in ctx[-6:]:
        print('    ', c)
print(f'\n=== add x?,x?,#0x3978: {len(adds)}')
for a, t, ctx in adds:
    print(f'  {a:#x}: {t}   <- {ctx[-2:]}')
print(f'\n=== сравнений с 0x2a..0x2f: {len(cmps)}')
for a, t, prev, fr in cmps:
    if fr:
        print(f'\n--- {a:#x}: {t}  (поле 0x3978 читалось рядом)')
        for c in prev[-4:]:
            print('    ', c)
