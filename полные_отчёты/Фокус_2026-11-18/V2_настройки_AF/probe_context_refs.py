import sys
sys.path.insert(0,r'<корень проекта>\Анализ_прошивки\Сравнение_версий_2026-11-16')
from fwcommon import *
for idx, pairs in [(0,[(0x17529d8,[0x11da77c,0x11da7b0,0x12d6da8,0x12d6e04,0x12dc554]),(0x18bb198,[0x12e6910,0x12e6940,0x1328720,0x13287b0,0x132e3f4,0x132f088])]),(1,[(0x17529d8,[0x2bf1e00]),(0x3bcab48,[0x2d9a190,0x2d9a198,0x2d9a1e0,0x2d9a1e8,0x2d9a360,0x2d9a374]),(0x4b8d230,[0x2f3c3f0,0x2f3c400,0x2f3c40c])])]:
 b=load('X-H2','old',idx); print('\nBLOCK',idx)
 for target,sites in pairs:
  print('\nTARGET',hex(target),'refs',adrp_refs(b,target)[:15])
  for site in sites:
   print('\nSITE',hex(site)); print(dis(b,site,18))
