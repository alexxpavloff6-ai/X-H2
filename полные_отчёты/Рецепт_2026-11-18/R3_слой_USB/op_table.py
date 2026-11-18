import sys,struct
sys.path.insert(0, r'<корень проекта>\Анализ_прошивки\Сравнение_версий_2026-11-16')
from fwcommon import *
b=load('X-H2','old',1)
for a in [0x33b10e8,0x33b10d0,0x33b10e0,0x33b1100]:
 print(hex(a),b.data[b.off(a):b.off(a)+160].hex(' '))
 print([hex(struct.unpack_from('<H',b.data,b.off(a)+2*i)[0]) for i in range(50)])
