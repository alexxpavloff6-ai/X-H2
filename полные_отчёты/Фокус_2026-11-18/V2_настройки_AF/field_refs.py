import sys
sys.path.insert(0,r'<корень проекта>\Анализ_прошивки\Сравнение_версий_2026-11-16')
from fwcommon import *
b=load('X-H2','old',1)
for t in [0x2680474,0x2680478,0x268047c,0x3bcab48,0x3bca000,0x3bcdfc0,0x3bcdfc0+0x3478,0x3bcd000]:
 refs=adrp_refs(b,t)
 print('\nTARGET',hex(t),'refs',len(refs))
 for x in refs[:100]: print(x['insn'])
