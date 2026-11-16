# -*- coding: utf-8 -*-
"""D: как в большой брекет-функции X-H2 (кандидат 0x2dd1478..) задаётся база
таблицы кадров x24/x25 (та, к которой прибавляется 0x1cfc000 в копировщике).
Печатает все места с участием x24/x25 и вызовы подготовки/копировщика.
"""
import sys, re
sys.path.insert(0, r'<корень проекта>\Анализ_прошивки\Сравнение_версий_2026-11-16\D_брекетинг')
from dhelp import *  # noqa

b = load('X-H2', 'new', 1)
lo, hi = 0x2dd1478, 0x2dd2400
for x in all_insns(b, lo, hi):
    o = x.op_str
    if not re.search(r'\bx2[45]\b|\bw2[45]\b', o):
        continue
    if x.mnemonic in ('bl', 'b') and 'x2' in o:
        pass
    print(f'{x.address:#010x}: {x.mnemonic:8} {o}')
