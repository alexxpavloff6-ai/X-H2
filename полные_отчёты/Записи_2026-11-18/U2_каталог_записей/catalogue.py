import sys,re,json
from pathlib import Path
sys.path.insert(0,r'<корень проекта>\Анализ_прошивки\Сравнение_версий_2026-11-16')
from fwcommon import load,bl_callers,func_start,insns,dis
OUT=Path(__file__).resolve().parent
blocks=[load('X-H2','old',i) for i in range(3)]
TARGETS={'set':0x14CF124,'get':0x14CF354,'scalar':0x14CF404,'rpc':0x14CF45C,'set_wrap_14CEDAC':0x14CEDAC,'set_wrap_14D098C':0x14D098C,'set_wrap_14D0A08':0x14D0A08}
def imm_w0(b,s):
    rows=[]
    start=max(b.base,s-0x30)
    for i in insns(b,start,min(12,(s-start)//4+1)):
        if i.address>=s: break
        if i.mnemonic in ('bl','blr','b','ret'): rows=[]
        m=re.fullmatch(r'mov(?:z)? w0, #(0x[0-9a-f]+|\d+)',i.mnemonic+' '+i.op_str)
        if m: rows=[int(m.group(1),0)]
    return rows[-1] if rows else None
result={}
for name,t in TARGETS.items():
 rows=[]
 for bi,b in enumerate(blocks):
  for s,k in bl_callers(b,t):
   fs=func_start(b,s); val=imm_w0(b,s)
   rows.append({'block':bi,'site':hex(s),'kind':k,'function':hex(fs) if fs else None,'w0':hex(val) if val is not None else None,'context':dis(b,s-0x20,10)})
 result[name]=rows
OUT.joinpath('xref_api.json').write_text(json.dumps(result,ensure_ascii=False,indent=2)+'\n',encoding='utf-8')
summary={k:{'count':len(v),'by_block':{str(i):sum(r['block']==i for r in v) for i in range(3)},'ids':sorted(set(r['w0'] for r in v if r['w0']))} for k,v in result.items()}
print(json.dumps(summary,ensure_ascii=False,indent=2))
