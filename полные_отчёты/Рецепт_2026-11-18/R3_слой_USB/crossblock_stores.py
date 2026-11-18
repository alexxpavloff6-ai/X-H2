import sys
sys.path.insert(0, r'<корень проекта>\Анализ_прошивки\Сравнение_версий_2026-11-16')
from fwcommon import *
for idx in [0,2,3]:
 b=load('X-H2','old',idx)
 print('\nBLOCK',idx)
 for off in [0x8f0,0x8f4]:
  rows=[]
  for va,w in iter_words(b):
   for size,op in [(1,0x39000000),(2,0x79000000),(4,0xb9000000),(8,0xf9000000)]:
    if (w&0xffc00000)==op and (((w>>10)&0xfff)*size)==off:
     q=insns(b,va,1)
     if q: rows.append((va,q[0].mnemonic,q[0].op_str))
  print('offset',hex(off),'n',len(rows))
  for r in rows: print(hex(r[0]),r[1],r[2])
