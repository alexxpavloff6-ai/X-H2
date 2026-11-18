import sys,struct
from pathlib import Path
sys.path.insert(0,r'<корень проекта>\Анализ_прошивки\Сравнение_версий_2026-11-16')
from fwcommon import load,dis,bl_callers,func_start,insns
b0=load('X-H2','old',0); b1=load('X-H2','old',1)
for a in (0x14CEDAC,0x14D098C): print('\n===',hex(a),'===\n',dis(b0,a,80))
for target in (0x14CEDAC,0x14D098C):
 print('\n### caller contexts',hex(target))
 for s,k in bl_callers(b0,target):
  fs=func_start(b0,s) or s-0x20
  print('\n--',hex(s),'fn',hex(fs),'--')
  print(dis(b0,max(fs,s-0x30),min(14,(s-max(fs,s-0x30))//4+1)))
# load raw service module without cache writes
DAT=Path(r'<корень проекта>\FIRMWARE\ver 5.30\FWUP0028.DAT')
raw=DAT.read_bytes(); inv=raw.translate(bytes.maketrans(bytes(range(256)),bytes(255-i for i in range(256))))[:0x300274]
loader=type('B',(),{})(); loader.data=inv[0x60274:0x60274+0x1e340]; loader.base=0x40000; loader.off=lambda self,va:va-self.base
# module helper imports Cs from fwcommon
from fwcommon import cs
for a in (0x4BC90,0x4BBD4,0x4C538,0x4C090):
 print('\n=== loader',hex(a),'===')
 off=a-loader.base
 print('\n'.join(f'{i.address:x}: {i.mnemonic} {i.op_str}' for i in cs.disasm(loader.data[off:off+0x180],a)))


