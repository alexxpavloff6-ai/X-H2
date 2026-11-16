# -*- coding: utf-8 -*-
"""D6: путь установки значения свойства 0x2B9 в блоке 0.

Находим функцию, содержащую запись 0x128c5d8 (strb w19,[settings+0x144]), её начало,
вызывающих и их аргументы (w19 = значение). Печатаем контекст вызовов и строки.
"""
import sys, re, struct
sys.path.insert(0, r'<корень проекта>\Анализ_прошивки\Сравнение_версий_2026-11-16\D_брекетинг')
from dhelp import *  # noqa

b = load('X-H2', 'new', 0)
d = b.data
ANCHOR = 0x128c5d8

# 1) начало функции: идём назад до пролога stp x29,x30,[sp,#-N]!, перед которым ret/b
start = None
for a in range(ANCHOR & ~3, ANCHOR - 0x4000, -4):
    w = struct.unpack_from('<I', d, b.off(a))[0]
    if (w & 0xffc07fff) == 0xa9807bfd:
        nxt = insns(b, a + 4, 1)
        if nxt and nxt[0].mnemonic == 'mov' and nxt[0].op_str == 'x29, sp':
            start = a
            break
print('начало функции:', hex(start) if start else None)
if start:
    print(dis(b, start, 12))

# 2) вызывающие
callers = bl_callers(b, start) if start else []
print('\nвызывающие:', [hex(a) for a, _ in callers])
for a, kind in callers[:8]:
    print(f'\n--- вызов {a:#x} ({kind}) ---')
    for x in all_insns(b, a - 0x40, a + 8):
        if x.mnemonic != '.byte':
            print(f'   {x.address:#x}: {x.mnemonic:8} {x.op_str}')
