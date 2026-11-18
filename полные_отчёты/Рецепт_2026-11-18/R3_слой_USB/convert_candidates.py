import sys
sys.path.insert(0, r'<корень проекта>\Анализ_прошивки\Сравнение_версий_2026-11-16')
from fwcommon import *
b=load('X-H2','old',1)
for a,n in [(0x2c86350,80),(0x2a49bc0,140),(0x2a4e9d0,100),(0x2c12f50,100),(0x2bf8b44,80),(0x2bf1df8,50)]: print('\n===',hex(a),'===\n',dis(b,a,n))
