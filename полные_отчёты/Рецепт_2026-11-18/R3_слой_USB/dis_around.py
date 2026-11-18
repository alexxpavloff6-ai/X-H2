import sys
sys.path.insert(0, r'<корень проекта>\Анализ_прошивки\Сравнение_версий_2026-11-16')
from fwcommon import *
b=load('X-H2','old',1)
for a,n in [(0x2f2c838,70),(0x2f2cde0,100),(0x2f2c8c0,40),(0x2f2ce80,45),(0x2f2c800,40)]:
 print('\n===',hex(a),'===\n',dis(b,a,n))
