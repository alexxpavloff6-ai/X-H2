import sys,struct
sys.path.insert(0,r'<корень проекта>\Анализ_прошивки\Сравнение_версий_2026-11-16')
from fwcommon import *
for idx in range(3):
 b=load('X-H2','old',idx); print('BLOCK',idx)
 for addr in [0x17529d8,0x18bb198,0x18bb2b8,0x1905c18,0x1905da8,0x442320,0x3bcab48,0x3bcdfc0,0x4b8d230]:
  for width in [4,8]:
   pos=find_bytes(b,struct.pack('<I' if width==4 else '<Q',addr))
   if pos: print(hex(addr),width,'literal refs', [hex(x) for x in pos[:20]])
  page=adrp_sites(b,addr)
  if page: print(hex(addr),'ADRP sites',[(hex(v),r) for v,r in page[:20]])
