import sys,struct
sys.path.insert(0, r'<корень проекта>\Анализ_прошивки\Сравнение_версий_2026-11-16')
from fwcommon import *
b=load('X-H2','old',1)
for ident in [0xdc,0x106,0x107,0x108]:
 idx=ident-0xb; v=struct.unpack_from('<h',b.data,b.off(0x33a77e8+2*idx))[0]; target=0x2c88f50+v*4
 print('\nID',hex(ident),'idx',idx,'rel',v,'target',hex(target)); print(dis(b,target,55))
