import sys,struct
sys.path.insert(0,r'<корень проекта>\Анализ_прошивки\Сравнение_версий_2026-11-16')
from fwcommon import load
b=load('X-H2','old',0)
for a,n,s in [(0x18bb198,12,0x10),(0x18bb2b8,12,0x10),(0x18bbbc0,11,0x18),(0x18bbcf0,27,0x1c)]:
 print(hex(a),[(hex(struct.unpack_from('<I',b.data,b.off(a+i*s))[0]),hex(a+i*s)) for i in range(n)])
