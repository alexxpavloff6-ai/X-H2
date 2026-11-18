import sys
from pathlib import Path
sys.dont_write_bytecode=True
sys.path.insert(0,r'<корень проекта>\Анализ_прошивки\Сравнение_версий_2026-11-16')
from fwcommon import load,dis,bl_callers
b=load('X-H2','old',1)
for a,n in [(0x2bf2248,100),(0x2bf2918,48),(0x2bf2a8c,48),(0x2bf2af4,48),(0x2bf2c0c,48),(0x2bf2ca0,48),(0x2bf2d2c,48),(0x2bf2db4,48),(0x2bf2e3c,48),(0x2bf2ea0,48),(0x2d3ce38,48),(0x2d3ce6c,48),(0x2c33fe8,48)]:
 print('\n',hex(a),'\n',dis(b,a,n),'\nCALLERS',[(hex(c),k) for c,k in bl_callers(b,a)][:12])
