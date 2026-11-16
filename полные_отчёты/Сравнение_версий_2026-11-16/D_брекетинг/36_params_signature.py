# -*- coding: utf-8 -*-
"""D3: поиск читателей блока params по «сигнатуре» полей.

params (0x68 байт, начало записи) заполняется так: +0x00, +0x0a..+0x18 (8×i16),
+0x1a, +0x1c..+0x22 (4×i16), +0x24, +0x26, +0x28..+0x2e (4×i16), +0x38, +0x4c,
+0x4e, +0x60. Ищем функции, в которых на один и тот же регистр-базу есть чтения
двух и более из «редких» полей (+0x1c, +0x1e, +0x24, +0x26, +0x2e, +0x4c, +0x4e, +0x60).
"""
import sys, re
sys.path.insert(0, r'<корень проекта>\Анализ_прошивки\Сравнение_версий_2026-11-16\D_брекетинг')
from dhelp import *  # noqa
from collections import defaultdict

model, state = 'X-H2', 'new'
b = load(model, state, 1)
d = b.data
starts = []
for o in range(0, len(d) - 3, 4):
    w = struct.unpack_from('<I', d, o)[0]
    if (w & 0xffc07fff) == 0xa9807bfd:
        starts.append(b.base + o)
starts.sort()

def func_of(addr):
    lo, hi = 0, len(starts) - 1
    while lo < hi:
        mid = (lo + hi + 1) // 2
        if starts[mid] <= addr:
            lo = mid
        else:
            hi = mid - 1
    return starts[lo]

RARE = {0x1c, 0x1e, 0x22, 0x24, 0x26, 0x2e, 0x4c, 0x4e, 0x60}
per = defaultdict(lambda: defaultdict(list))   # func -> reg -> [(off, addr, mnem)]
for x in all_insns(b):
    if x.mnemonic == '.byte' or not x.mnemonic.startswith('ldr'):
        continue
    m = re.search(r'\[(x\d+), #0x([0-9a-f]+)\]', x.op_str)
    if not m:
        continue
    off = int(m.group(2), 16)
    if off not in RARE:
        continue
    f = func_of(x.address)
    per[f][m.group(1)].append((off, x.address, f'{x.mnemonic} {x.op_str}'))

print('функции с совпадением сигнатуры:')
for f, regs in sorted(per.items()):
    for reg, lst in regs.items():
        offs = {o for o, _, _ in lst}
        if len(offs) >= 2 and (0x60 in offs):
            print(f'\n=== функция {f:#x}, база {reg}, поля {sorted(hex(o) for o in offs)}')
            for o, a, s in sorted(lst)[:6]:
                print(f'    {a:#x}: {s}')
