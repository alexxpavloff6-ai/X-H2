import sys
sys.path.insert(0,r'<корень проекта>\Анализ_прошивки\Сравнение_версий_2026-11-16')
from fwcommon import *
b=load('X-H2','old',1)
for a in [0x2bd5114,0x2bd56d0,0x2bf8784,0x2bf8848,0x2c99ee4,0x2c9a074,0x2f3c3f0]:
 print('\nFUNC',hex(a),'start',hex(func_start(b,a) or 0))
 print('callers',[hex(x[0]) for x in bl_callers(b,a)[:30]])
 start=func_start(b,a) or a
 if a in [0x2bd5114,0x2c99ee4]: print(dis(b,start,150))
