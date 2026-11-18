import sys
sys.path.insert(0, r'<корень проекта>\Анализ_прошивки\Сравнение_версий_2026-11-16')
from fwcommon import *
b=load('X-H2','old',0)
for a,n in [(0x11335c4,80),(0x12aa788,100),(0x11da370,60)]: print('\n===',hex(a),'===\n',dis(b,a,n))
for t in [0x11335c4,0x11da370,0x12aa788]: print('CALLERS',hex(t),[(hex(a),k) for a,k in bl_callers(b,t)[:30]])
