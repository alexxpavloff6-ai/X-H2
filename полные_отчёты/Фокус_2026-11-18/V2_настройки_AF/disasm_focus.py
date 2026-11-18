import sys,struct
sys.path.insert(0,r'<корень проекта>\Анализ_прошивки\Сравнение_версий_2026-11-16')
from fwcommon import *
for idx,funcs in [(1,[0x2c88e98,0x2c8a2a8,0x2c90f9c,0x2bd5114,0x2bd56d0,0x2bf8784,0x2bf8848,0x2bf87a8,0x2bf8808]),(0,[0x113a668,0x11335ec,0x1135930,0x1141ee0])]:
 b=load('X-H2','old',idx)
 for a in funcs:
  print('\n---',hex(a),'---'); print(dis(b,a,60))
