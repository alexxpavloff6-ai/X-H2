import sys
sys.path.insert(0,r'<корень проекта>\Анализ_прошивки\Сравнение_версий_2026-11-16')
from fwcommon import load,dis
b=load('X-H2','old',1)
for a in [0x2a033e8,0x2bd3298,0x2bf0c45,0x2bfa948,0x2cb4240,0x2cc2e00,0x2cfb8f0,0x2c0f228,0x2c0f574,0x2c0f8bc,0x2c0fb0c,0x2c0fd54]:
 print('\n',hex(a),'\n',dis(b,a-36,25))
