import sys
sys.path.insert(0, r'<корень проекта>\Анализ_прошивки\Сравнение_версий_2026-11-16')
from fwcommon import *
b=load('X-H2','old',1)
for a in [0x2bdce6c,0x2db84c0,0x2db84f8,0x2eed7d0,0x2fca1dc,0x30b8048,0x31769a0,0x2bcb834,0x2bcb854,0x2bcb880,0x2ef5b50,0x30b8050,0x30d5b64]:
 print('\n===',hex(a),'func',hex(func_start(b,a) or 0),'===\n',dis(b,a-40,30))
