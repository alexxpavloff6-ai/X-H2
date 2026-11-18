import sys,re
sys.path.insert(0,r'<корень проекта>\Анализ_прошивки\Сравнение_версий_2026-11-16')
from fwcommon import *
b=load('X-H2','old',1)
for x in cs.disasm(b.data,b.base):
 if any(s in x.op_str.lower() for s in ['#0x3978','#0x3478','#0x1994','#0x19ac']): print(f'{x.address:x}: {x.mnemonic} {x.op_str}')
