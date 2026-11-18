import sys
sys.path.insert(0,r'<корень проекта>\Анализ_прошивки\Сравнение_версий_2026-11-16')
from fwcommon import *
b=load('X-H2','old',1)
for t in [0x1141ee0,0x2bd5114,0x2c99ee4,0x2bd56d0,0x2bf6704,0x2bf51cc]:
 print('\nTARGET',hex(t),'callers',[hex(x[0]) for x in bl_callers(b,t)[:100]])
for a in [0x2bd56d0,0x2bd57bc,0x2bd59ec,0x2bd5998,0x2bd5a24,0x2c99e00,0x2f3c3ec]:
 print('\n',hex(a)); print(dis(b,a,48))
