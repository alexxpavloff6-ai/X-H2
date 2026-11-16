# -*- coding: utf-8 -*-
"""D4: домен значений [ctx+0x3978] — строгий скан.

Для каждого `ldr wN,[xB,#0x3978]` смотрим только СЛЕДУЮЩИЕ 4 инструкции и ищем
`cmp wN,#imm` (или `cmp wN,wM`); регистр не должен перезаписываться. Так получаем
реальный перечень кодов режима, которые различает код.
"""
import sys, re
from collections import Counter, defaultdict, deque
sys.path.insert(0, r'<корень проекта>\Анализ_прошивки\Сравнение_версий_2026-11-16\D_брекетинг')
from dhelp import *  # noqa

MODEL, STATE = 'X-H2', 'new'
b = load(MODEL, STATE, 1)

recent = deque(maxlen=5)   # (addr, mnem, op_str, dst_reg_or_None, src_0x3978_reg_or_None)
rows = []
for x in all_insns(b):
    if x.mnemonic == '.byte':
        continue
    ops = x.op_str
    # 1) это чтение поля?
    m = re.search(r'\[x\d+, #0x3978\]', ops)
    src_reg = None
    dst = None
    if m and x.mnemonic in ('ldr', 'ldrh', 'ldrsw'):
        dst = ops.split(',')[0].strip()
        src_reg = dst[1:] if dst.startswith(('w', 'x')) else dst
    # 2) это cmp по регистру, который недавно читали?
    if x.mnemonic in ('cmp', 'subs'):
        op0 = ops.split(',')[0].strip()
        imm = re.search(r'#(0x[0-9a-f]+|\d+)', ops)
        reg = op0[1:] if op0.startswith(('w', 'x')) else op0
        for a, mn, o, d, sr in reversed(recent):
            if sr == reg:
                val = int(imm.group(1), 0) if imm else None
                rows.append((a, x.address, val, ops))
                break
    recent.append((x.address, x.mnemonic, ops, dst, src_reg))

cnt = Counter(v for _, _, v, _ in rows if v is not None)
print('строгих сравнений поля 0x3978:', len(rows), ' с иммедиатом:', sum(1 for r in rows if r[2] is not None))
print('значения:', dict(sorted(cnt.items())))
by_val = defaultdict(list)
for a, c, v, ops in rows:
    if v is not None:
        by_val[v].append((a, c, ops))
for v in sorted(by_val):
    print(f'\n{v:#04x}: ' + ', '.join(f'{a:#x}->{c:#x} ({o})' for a, c, o in by_val[v][:10]))
