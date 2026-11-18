import sys
sys.path.insert(0,r'<корень проекта>\Анализ_прошивки\Сравнение_версий_2026-11-16')
from fwcommon import load,dis,bl_callers
b=load('X-H2','old',1)
for a,n in [(0x2bf2394,50),(0x2bf2458,55),(0x2bf26d0,50),(0x2bf26ec,55),(0x2bf2f1c,60),(0x2bf2ff0,50),(0x2c053c8,60),(0x2c05890,45),(0x2c0b844,80),(0x2c13e4c,65)]:
 print('\n',hex(a),'\n',dis(b,a,n))
 print('CALLERS',[(hex(c),k) for c,k in bl_callers(b,a)][:20])
