import sys
sys.path.insert(0,r'<корень проекта>\Анализ_прошивки\Сравнение_версий_2026-11-16')
from fwcommon import load,dis
b=load('X-H2','old',1); b0=load('X-H2','old',0)
for a in [0x2c0b970,0x2c0b844,0x1135944,0x1135930,0x12e67ac,0x2c94a78,0x2c93fd4]:
 bb=b0 if a < b.base else b
 print('\n',hex(a),'\n',dis(bb,a,90))
