import sys
sys.path.insert(0, r'<корень проекта>\Анализ_прошивки\Сравнение_версий_2026-11-16')
from fwcommon import *
for idx in [0,1,2,3]:
 b=load('X-H2','old',idx)
 print('BLOCK',idx)
 for x in [0x201c,0x2001,0x2019]:
  print(hex(x),[hex(z) for z in find_bytes(b,x.to_bytes(2,'little'))[:60]])
