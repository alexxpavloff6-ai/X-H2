import sys
sys.path.insert(0, r'<корень проекта>\Анализ_прошивки\Сравнение_версий_2026-11-16')
from fwcommon import *
b=load('X-H2','old',1)
for t in [0x2c88e98,0x2c93fd4,0x1135930,0x2bf2ec0,0x2bf31a0,0x2f2cde0]:
 print('\nTARGET',hex(t))
 for site,kind in bl_callers(b,t):
  if kind=='bl': print(hex(site),'func',hex(func_start(b,site) or 0))
