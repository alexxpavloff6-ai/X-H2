import sys,struct
sys.path.insert(0, r'<корень проекта>\Анализ_прошивки\Сравнение_версий_2026-11-16')
from fwcommon import *
for idx,addrs in [(0,[0x17529d8,0x18bb198,0x18bb2b8,0x1905c18,0x1905da8]),(1,[0x2bd56d0,0x2bf8784]),(2,[0x442320])]:
 b=load('X-H2','old',idx); print('\n### BLOCK',idx,b)
 for a in addrs:
  print('\nADDR',hex(a),'u16:',[hex(struct.unpack_from('<H',b.data,b.off(a)+i)[0]) for i in range(0,48,2)])
  refs=adrp_refs(b,a)
  print('REFS',refs[:10], 'n=',len(refs))
  for row in refs[:3]: print(dis(b, row['site']-12,12))
