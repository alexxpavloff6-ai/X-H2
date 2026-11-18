import sys
sys.path.insert(0, r'<корень проекта>\Анализ_прошивки\Сравнение_версий_2026-11-16')
from fwcommon import *
b=load('X-H2','old',1)
for a,n in [(0x2bdfa00,100),(0x2bcb7b0,80),(0x2c12f00,70),(0x2c02000,100),(0x2bfb6c0,60),(0x2c64bc0,50),(0x2c71900,50)]: print('\n===',hex(a),'===\n',dis(b,a,n))
