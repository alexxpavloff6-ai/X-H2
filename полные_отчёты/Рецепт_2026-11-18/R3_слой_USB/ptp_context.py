import sys
sys.path.insert(0, r'<корень проекта>\Анализ_прошивки\Сравнение_версий_2026-11-16')
from fwcommon import *
b=load('X-H2','old',1)
print(dis(b,0x2bdf9c4,100))
print('callers',[(hex(x),k) for x,k in bl_callers(b,0x2bdf9c4)[:50]])
