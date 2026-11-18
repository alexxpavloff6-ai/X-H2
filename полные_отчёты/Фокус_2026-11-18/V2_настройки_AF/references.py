import sys
sys.path.insert(0,r'<корень проекта>\Анализ_прошивки\Сравнение_версий_2026-11-16')
from fwcommon import *
for idx in (0,1,2):
 b=load('X-H2','old',idx); print('BLOCK',idx,b)
 for target in [0x2c93fd4,0x12aa788,0x113a668,0x11335ec,0x1135930,0x11335c4,0x1141ee0,0x2c88e98]:
  c=bl_callers(b,target)
  if c: print(hex(target),len(c),[hex(x[0]) for x in c[:20]])
 for t in [0x17529d8,0x18bb198,0x18bb2b8,0x1905c18,0x1905da8,0x442320]:
  refs=adrp_refs(b,t)
  if refs: print('refs',hex(t),len(refs),refs[:10])
