import sys
sys.path.insert(0, r'<корень проекта>\Анализ_прошивки\Сравнение_версий_2026-11-16')
from fwcommon import *
b=load('X-H2','old',0)
for t in [0x131ff1c,0x18caa94,0x3443000,0x3443590,0x2c88e98,0x2c93fd4]:
 print('\n',hex(t),'refs',adrp_refs(b,t,24),'callers',[(hex(x),k) for x,k in bl_callers(b,t)[:30]])
print('\nMAP FN\n',dis(b,0x131ff1c,100))
