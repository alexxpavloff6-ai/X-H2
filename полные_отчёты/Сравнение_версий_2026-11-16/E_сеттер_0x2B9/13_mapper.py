# -*- coding: utf-8 -*-
"""E13: функция-маппер «индекс поля -> id свойства» (район 0x1137b0c..0x1138e2c):
её вход, аргументы, вызывающие и вызовы с индексом 8."""
import sys, re, struct
sys.path.insert(0, r'<корень проекта>\Анализ_прошивки\Сравнение_версий_2026-11-16\E_сеттер_0x2B9')
from ecommon import *  # noqa

MODEL, STATE = 'X-H2', 'new'
b = load(MODEL, STATE, 0)

print('=== 0x1137a60..0x1137b30 ===')
dump_range(b, 0x1137a60, 0x1137b30)

print('\n=== прологи в 0x1136000..0x1137b0c ===')
for x in all_insns(b, 0x1136000, 0x1137b0c):
    if x.mnemonic == '.byte':
        continue
    if x.mnemonic == 'stp' and 'x29, x30, [sp, #-' in x.op_str:
        print(f'  {x.address:x}: {x.mnemonic} {x.op_str}')

print('\n=== все bl/b на 0x1137b08 (общий эпилог) ===')
print([hex(a) for a, k in bl_callers(b, 0x1137b08)][:20], 'count', len(bl_callers(b, 0x1137b08)))

# ищем, кто читает epilogue: ищем инструкции b 0x1137b08 и группируем
print('\n=== адреса, откуда b 0x1137b08 (первые 20) ===')
print([hex(a) for a, k in bl_callers(b, 0x1137b08)][:20])
