import sys
sys.path.insert(0,r'<корень проекта>\Анализ_прошивки\Сравнение_версий_2026-11-16')
from fwcommon import load,adrp_refs,dis
b=load('X-H2','old',1)
for a in [0x26BDF70,0x26BDF74,0x26BDF78]:
 refs=adrp_refs(b,a,24); print('\nTARGET',hex(a),'refs',len(refs))
 for x in refs[:100]: print(x['insn'],'\n',dis(b,x['site']-16,12))
