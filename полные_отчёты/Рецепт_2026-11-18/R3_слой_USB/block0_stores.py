import sys
sys.path.insert(0, r'<корень проекта>\Анализ_прошивки\Сравнение_версий_2026-11-16')
from fwcommon import *
b=load('X-H2','old',0)
for a in [0x12ec8b0,0x12ec948,0x1230a70,0x1231af0,0x14e73e4,0x14e7408,0x155ce00,0x1571838]:
 print('\n===',hex(a),'func',hex(func_start(b,a) or 0),'===\n',dis(b,a-44,32))
