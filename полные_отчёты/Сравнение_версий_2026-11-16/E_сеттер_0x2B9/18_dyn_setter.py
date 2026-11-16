# -*- coding: utf-8 -*-
"""E18: вызовы API установки свойства 0x11335c4 с НЕлитеральным id: контекст 14 инструкций.
Цель — найти табличные/вычисляемые id и путь к 0x2B9."""
import sys, re, struct
sys.path.insert(0, r'<корень проекта>\Анализ_прошивки\Сравнение_версий_2026-11-16\E_сеттер_0x2B9')
from ecommon import *  # noqa

MODEL, STATE = 'X-H2', 'new'
b = load(MODEL, STATE, 0)
TGT = 0x11335c4

rows = []
for a, k in bl_callers(b, TGT):
    if k != 'bl':
        continue
    hist = [x for x in all_insns(b, a - 0x60, a) if x.mnemonic != '.byte']
    lit = None
    for y in reversed(hist):
        if y.mnemonic in ('mov', 'movz') and re.match(r'w0, #', y.op_str):
            lit = int(y.op_str.split('#')[1], 0)
            break
        if re.match(r'w0,', y.op_str) and y.mnemonic not in ('cmp', 'cmn', 'tst'):
            lit = None
            break
    if lit == 0x2b9:
        rows.append((a, 'LIT2B9', hist))
    elif lit is None:
        rows.append((a, 'DYN', hist))

print(f'вызовов {TGT:#x}: всего {len([1 for a,k in bl_callers(b,TGT)])}; DYN/LIT2B9: {len(rows)}')
for a, tag, hist in rows:
    print(f'\n=== {a:#x} [{tag}] ===')
    for y in hist[-14:]:
        print(f'  {y.address:x}: {y.mnemonic:8} {y.op_str}')
