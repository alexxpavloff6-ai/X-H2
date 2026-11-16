# -*- coding: utf-8 -*-
"""D4: домен значений поля [ctx+0x3978]: все сравнения поля с иммедиатами.

Сканируем блок 1: находим `ldr wN,[xB,#0x3978]`, затем в пределах 6 инструкций —
`cmp wN,#imm` (или `subs`), собираем гистограмму imm и адреса. Это даёт перечень
кодов режима, которые реально различает код.
"""
import sys, re, struct
from collections import Counter, defaultdict
sys.path.insert(0, r'<корень проекта>\Анализ_прошивки\Сравнение_версий_2026-11-16\D_брекетинг')
from dhelp import *  # noqa

MODEL, STATE = 'X-H2', 'new'
b = load(MODEL, STATE, 1)

rows = []
pending = []       # (addr, reg)
for x in all_insns(b):
    if x.mnemonic == '.byte':
        continue
    m = re.search(r'\[(x\d+), #0x3978\]', x.op_str)
    if m and x.mnemonic in ('ldr', 'ldrh', 'ldrsw'):
        # регистр назначения
        dst = x.op_str.split(',')[0].strip()
        reg = dst[1:] if dst.startswith('w') else dst
        pending.append((x.address, reg))
    # сравнение с иммедиатом
    if x.mnemonic in ('cmp', 'subs', 'adds') and pending:
        mm = re.search(r'#(0x[0-9a-f]+|\d+)', x.op_str)
        if mm:
            val = int(mm.group(1), 0)
            op0 = x.op_str.split(',')[0].strip()
            for a, reg in pending[-3:]:
                if op0 in (reg, 'w' + reg, 'x' + reg):
                    rows.append((a, x.address, val, reg))
                    break
    # сбрасываем «ожидание» через 8 инструкций
    if len(pending) > 40:
        pending = pending[-20:]

cnt = Counter(v for _, _, v, _ in rows)
print('сравнений поля 0x3978 с imm:', len(rows))
print('гистограмма значений:', dict(sorted(cnt.items())))
by_val = defaultdict(list)
for a, c, v, reg in rows:
    by_val[v].append((a, c))
for v in sorted(by_val):
    print(f'\n  значение {v:#04x}: {len(by_val[v])} сравнений, напр. ' +
          ', '.join(f'{a:#x}->{c:#x}' for a, c in by_val[v][:6]))
