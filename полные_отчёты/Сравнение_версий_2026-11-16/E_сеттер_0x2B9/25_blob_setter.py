# -*- coding: utf-8 -*-
"""E25: (1) w19 (база страницы свойств) в функции-заполнителе 0x2de8ff4;
(2) кто пишет байтовый blob настроек [0x20bf458] — сеттер и его вызовы;
(3) поиск записи значения 0x2C в id 0x28013/0x28xxx."""
import sys, re, struct
sys.path.insert(0, r'<корень проекта>\Анализ_прошивки\Сравнение_версий_2026-11-16\E_сеттер_0x2B9')
from ecommon import *  # noqa

b1 = load('X-H2', 'new', 1)
b0 = load('X-H2', 'new', 0)

print('=== присваивания w19 в fill-функции 0x2de8ff4 (до 0x2debac0) ===')
for x in all_insns(b1, 0x2de8ff4, 0x2debac0):
    if x.mnemonic == '.byte':
        continue
    if re.match(r'w19,', x.op_str) and x.mnemonic in ('mov', 'add', 'sub', 'orr', 'ldr'):
        print(f'  {x.address:#x}: {x.mnemonic} {x.op_str}')

print('\n=== ссылки на глобал 0x20bf458 (указатель на blob настроек), блок 0 ===')
rows = adrp_refs(b0, 0x20bf458, window=14)
print('найдено:', len(rows))
for r in rows[:40]:
    print('  ', r['insn'])
