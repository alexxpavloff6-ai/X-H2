# -*- coding: utf-8 -*-
"""E2: найти вход в диспетчер установки свойств блока 0 (район 0x128c..., запись 0x2B9)
и разобрать способ выбора ветки по id.
"""
import sys, re, struct
sys.path.insert(0, r'<корень проекта>\Анализ_прошивки\Сравнение_версий_2026-11-16\E_сеттер_0x2B9')
from ecommon import *  # noqa

MODEL, STATE = 'X-H2', 'new'
b = load(MODEL, STATE, 0)

# 1) все mov w0,#0x2b9 в блоке 0 и окрестности 16 инструкций
print('=== mov w0,#0x2b9 ===')
for va, w in iter_words(b):
    if w == 0x52805720:  # movz w0,#0x2b9 (imm16=0x2b9, hw=0) -> 0x52800000|(0x2b9<<5)|0
        print(f'  {va:#x}')
        dump_range(b, va - 0x40, va + 0x30)
        print()

# 2) ищем точку входа: заголовки с movz/cmp/b.hi/ldrh/adr/br перед 0x128c518
print('\n=== поиск jump-таблицы (ldrh [.., w, uxtw #1]) в 0x128b000..0x128c700 ===')
for x in all_insns(b, 0x128b000, 0x128c700):
    if x.mnemonic == '.byte':
        continue
    if x.mnemonic in ('ldrh', 'ldrb') and 'uxtw' in x.op_str:
        print(f'  {x.address:x}: {x.mnemonic} {x.op_str}')
    if x.mnemonic == 'br':
        print(f'  {x.address:x}: br {x.op_str}')

# 3) ищем все прологи (stp x29,x30 / sub sp,sp) перед 0x128c518
print('\n=== прологи/границы в 0x128b000..0x128c520 ===')
for x in all_insns(b, 0x128b000, 0x128c520):
    if x.mnemonic == '.byte':
        continue
    if x.mnemonic == 'stp' and 'x29, x30, [sp, #-' in x.op_str:
        print(f'  {x.address:x}: stp ...')
    if x.mnemonic == 'sub' and x.op_str.startswith('sp, sp,'):
        print(f'  {x.address:x}: sub sp ... -> {x.op_str}')
