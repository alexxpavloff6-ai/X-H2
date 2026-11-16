# -*- coding: utf-8 -*-
"""E14: функция-маппер полей 0x1136130 (parent_id, field_index) -> child_property_id.
Разбор всех чанков региона, поиск parent для 0x2b9, вызывающих и вызовов с индексом 8.
"""
import sys, re, struct
sys.path.insert(0, r'<корень проекта>\Анализ_прошивки\Сравнение_версий_2026-11-16\E_сеттер_0x2B9')
from ecommon import *  # noqa

MODEL, STATE = 'X-H2', 'new'
b = load(MODEL, STATE, 0)
F = 0x1136130

print('=== вход функции ===')
dump_range(b, F, F + 0x50)
print('callers:', [hex(a) for a, k in bl_callers(b, F)])
for a, k in bl_callers(b, F):
    print(f'\n--- call {a:#x} ---')
    dump_range(b, a - 0x40, a + 0x10)

# разбор чанков: ищем cmp w0,#imm сразу после ret (0x1137b08)
print('\n=== чанки: cmp w0,#parent и их диапазон ===')
starts = []
prev = None
for x in all_insns(b, 0x1137b00, 0x1138e2c):
    if x.mnemonic == '.byte':
        continue
    if x.mnemonic == 'cmp' and re.match(r'w0, #0x[0-9a-f]+$', x.op_str):
        # ищем в пределах 3 инструкций перед этим 'ret'/'b'
        starts.append((x.address, int(x.op_str.split('#')[1], 0)))
for a, p in starts:
    print(f'  {a:#x}: parent {p:#x}')
