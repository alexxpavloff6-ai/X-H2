import sys
sys.path.insert(0, r'<корень проекта>\Анализ_прошивки\Сравнение_версий_2026-11-16')
from fwcommon import *
b=load('X-H2','old',1)
for t in [0x3443590,0x3443000,0x2bf2ec0,0x2bf31a0,0x2f2cde0,0x2f2c838,0x131ff1c,0x2c88e98,0x2c93fd4,0x1135930]:
 print('\nTARGET',hex(t),'ADRP',adrp_refs(b,t,16),'CALLERS',bl_callers(b,t)[:30])
