# -*- coding: utf-8 -*-
"""D6: switch «код события -> id свойства» в блоке 1 (X-H2 5.33, функция 0x2d3a500)
и ветка, где w19 = 0x2b9.

Печатает:
 - пролог/начало функции и разбор code&0xff00;
 - участок 0x2d3aa80..0x2d3ab40 (ветка 0x2b9 и соседние id 0x2ac..0x2bb);
 - участок перехода orr w19,#0x4000 -> 0x2d3ae3c;
 - обработчик 0x2d3bcf4.
"""
import sys, re
sys.path.insert(0, r'<корень проекта>\Анализ_прошивки\Сравнение_версий_2026-11-16\D_брекетинг')
from dhelp import *  # noqa

b = load('X-H2', 'new', 1)

def show(title, lo, hi):
    print(f'\n=== {title}: {lo:#x}..{hi:#x} ===')
    for x in all_insns(b, lo, hi):
        if x.mnemonic == '.byte':
            continue
        print(f'{x.address:#x}: {x.mnemonic:8} {x.op_str}')

show('начало 0x2d3a500', 0x2d3a500, 0x2d3a600)
show('ветка 0x2b9 / соседние id', 0x2d3aa80, 0x2d3ab40)
show('orr 0x4000 -> 0x2d3ae3c', 0x2d3a930, 0x2d3a980)
show('переход к обработчику', 0x2d3ae00, 0x2d3ae70)
show('обработчик 0x2d3bcf4', 0x2d3bcf4, 0x2d3bda0)
