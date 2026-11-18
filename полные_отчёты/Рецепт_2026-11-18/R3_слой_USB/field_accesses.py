import sys
sys.path.insert(0, r'<корень проекта>\Анализ_прошивки\Сравнение_версий_2026-11-16')
from fwcommon import *
b=load('X-H2','old',1)
for off in [0x8f0,0x8f4,0x1d4c]:
 print('\nOFFSET',hex(off))
 matches=[]
 for va,w in iter_words(b):
  # unsigned immediate LDR/STR, scaled by access size
  size=1<<(w>>30 & 3)
  if size>8 or off%size: continue
  imm=(w>>10)&0xfff
  if imm*size==off and (w & 0x3b000000) in (0x39000000,0x18000000):
   ins=insns(b,va,1)
   if ins: matches.append((va,ins[0].mnemonic,ins[0].op_str))
 print('count',len(matches))
 for a,m,o in matches: print(hex(a),m,o)
