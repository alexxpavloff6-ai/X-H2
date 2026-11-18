import sys
sys.path.insert(0, r'<корень проекта>\Анализ_прошивки\Сравнение_версий_2026-11-16')
from fwcommon import *
b=load('X-H2','old',1)
for va,w in iter_words(b):
 i=insns(b,va,1)
 if i and ('#0x8f0' in i[0].op_str or '#0x8f4' in i[0].op_str):
  if i[0].mnemonic.startswith(('stp','ldp','stur','ldur')): print(hex(va),i[0].mnemonic,i[0].op_str)
