import sys
sys.path.insert(0, r'<корень проекта>\Анализ_прошивки\Сравнение_версий_2026-11-16')
from fwcommon import *
b=load('X-H2','old',1)
for va,reg in adrp_sites(b,0x26a7000):
 seq=insns(b,va,16)
 txt=' | '.join(f'{z.mnemonic} {z.op_str}' for z in seq)
 if '#0x8f0' in txt or '#0x8f4' in txt:
  if any(z.mnemonic.startswith('str') and ('#0x8f0' in z.op_str or '#0x8f4' in z.op_str) for z in seq):
   print('\n',hex(va),txt)
