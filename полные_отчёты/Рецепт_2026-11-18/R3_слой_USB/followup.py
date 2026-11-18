import sys
sys.path.insert(0, r'<корень проекта>\Анализ_прошивки\Сравнение_версий_2026-11-16')
from fwcommon import *
b=load('X-H2','old',1)
for a in [0x2bdfbcc,0x2bdfbe0,0x2bdfc58,0x2bdfc64]:
 print(hex(a),'funcstart',func_start(b,a),'BL refs',[(hex(x),k) for x,k in bl_callers(b,a)[:50]])
print(dis(b,0x2bdfbcc,24))
