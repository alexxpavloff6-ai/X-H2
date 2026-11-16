# -*- coding: utf-8 -*-
"""E1: функция, содержащая запись 0x128c5d8 (strb w19,[settings+0x144], свойство 0x2B9).

Печатаем начало функции, контекст записи, ищем switch/jump-таблицу по id,
вызывающих функции, их аргументы.
"""
import sys, re, struct
sys.path.insert(0, r'<корень проекта>\Анализ_прошивки\Сравнение_версий_2026-11-16\E_сеттер_0x2B9')
from ecommon import *  # noqa

MODEL, STATE = 'X-H2', 'new'
b = load(MODEL, STATE, 0)
ANCHOR = 0x128c5d8

start = find_prologue(b, ANCHOR)
print('prologue:', hex(start) if start else None)
if start:
    print(dis(b, start, 14))

print('\n=== контекст вокруг 0x128c5d8 ===')
dump_range(b, ANCHOR - 0xc0, ANCHOR + 0x90)

# ищем в функции switch/jump-таблицу: ldrh/ldrb [xN,wM,uxtw] + adr + br
print('\n=== все ldrh/ldrb с uxtw и br внутри функции ===')
end = start + 0x4000
for x in all_insns(b, start, end):
    if x.mnemonic == '.byte':
        continue
    if x.mnemonic in ('ldrh', 'ldrb', 'ldrsh', 'ldrsb') and 'uxtw' in x.op_str:
        print(f'  {x.address:x}: {x.mnemonic} {x.op_str}')
    if x.mnemonic in ('br', 'br x'):
        print(f'  {x.address:x}: br {x.op_str}')
    if x.mnemonic == 'ret':
        pass

# вызывающие
print('\n=== вызывающие функции (bl) ===')
callers = bl_callers(b, start) if start else []
print('callers of', hex(start), [hex(a) for a, k in callers])
for a, kind in callers[:10]:
    print(f'\n--- call {a:#x} ---')
    dump_range(b, a - 0x50, a + 8)
