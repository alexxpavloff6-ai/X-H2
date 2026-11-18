import sys
sys.path.insert(0, r'<корень проекта>\Анализ_прошивки\Сравнение_версий_2026-11-16')
from fwcommon import *
b=load('X-H2','old',1)
for a,n in [(0x2ac7808,90),(0x2ac7af4,90),(0x2bf2fe4,75),(0x2bf3298,75),(0x2bf4e44,85),(0x2ac74c4,85)]:
 print('\n===',hex(a),'===\n',dis(b,a,n))
