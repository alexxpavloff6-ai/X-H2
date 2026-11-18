import sys
from pathlib import Path
sys.dont_write_bytecode=True
FW=Path(r'<корень проекта>\Анализ_прошивки\Сравнение_версий_2026-11-16')
sys.path.insert(0,str(FW))
print(FW,FW.exists(),sys.path[0])
from fwcommon import load,dis,bl_callers
for idx,addrs in [(0,[0x57d28]),(1,[0x2bf2248,0x2bf0220,0x2c13ff4,0x2c14020,0x2c05748]),(2,[0x57d28])]:
 b=load('X-H2','old',idx); print('\nBLOCK',idx,repr(b))
 for a in addrs:
  if b.base <= a < b.end:
   print('\nADDR',hex(a),'\n',dis(b,a,75))
   print('CALLERS',[(hex(c),k) for c,k in bl_callers(b,a)][:40])
