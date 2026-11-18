import sys
from pathlib import Path
sys.dont_write_bytecode=True
sys.path.insert(0,r'<корень проекта>\Анализ_прошивки\Сравнение_версий_2026-11-16')
from fwcommon import load,cs,dis,bl_callers,func_start,find_bytes
need={0x1015,0x1016,0x2001,0x2002,0x200A,0x2019,0x201C,0x80,0x40,0x100,0x2000}
for idx in [0,1,2]:
 b=load('X-H2','old',idx); hits=[]
 print('\nBLOCK',idx,repr(b))
 for i in cs.disasm(b.data,b.base):
  ops=i.op_str.replace(',',' ').replace('[',' ').replace(']',' ').split()
  imm=[]
  for t in ops:
   if t.startswith('#'):
    try: imm.append(int(t[1:],0))
    except: pass
  if any(n in imm for n in need): hits.append((i.address,i.mnemonic,i.op_str))
 print('IMM HITS',len(hits))
 for x in hits[:120]: print(hex(x[0]),x[1],x[2])
 for n in (0x2001,0x2002,0x200a,0x2019,0x201c,0x1015,0x1016):
  poss=find_bytes(b,n.to_bytes(2,'little')); print('raw',hex(n),[hex(x) for x in poss[:35]],'n',len(poss))
