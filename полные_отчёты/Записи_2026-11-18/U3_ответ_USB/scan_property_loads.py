import sys
sys.path.insert(0,r'<корень проекта>\Анализ_прошивки\Сравнение_версий_2026-11-16')
from fwcommon import load,cs,dis,func_start,bl_callers
b=load('X-H2','old',1); rows=[]
allx=list(cs.disasm(b.data,b.base))
for i,x in enumerate(allx):
 if '#0x1d4c' in x.op_str and x.mnemonic.startswith('ldr'):
  rows.append(x.address)
print('loads 1d4c',len(rows))
for a in rows[:150]: print('\n',hex(a),'func',hex(func_start(b,a) or a),'\n',dis(b,a-24,20))
