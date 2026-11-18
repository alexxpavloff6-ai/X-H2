import sys, json
from pathlib import Path
sys.dont_write_bytecode=True
FW=Path(r'<корень проекта>\Анализ_прошивки\Сравнение_версий_2026-11-16')
sys.path.insert(0,str(FW))
from fwcommon import load, dis, bl_callers, adrp_refs, insns, func_start, iter_words
b=load('X-H2','old',1)
# callers, selected disassemblies
out={'block':repr(b),'error_handler':dis(b,0x2C05748,90),'error_callers':[{'site':hex(a),'context':dis(b,a-0x28,16)} for a,k in bl_callers(b,0x2C05748) if k=='bl']}
# scan instructions for constants and exact command/status immediates
hits={}
needles={0x1015,0x1016,0x2001,0x2002,0x200A,0x2019,0x201C,0x80000080,0xF001,0xD195,0xD18E,0xD1A5,0x26C0DF4}
for va in range(b.base,b.end,4):
    try: ins=insns(b,va,1)
    except Exception: continue
    if not ins: continue
    x=ins[0]
    val=None
    for tok in x.op_str.replace('[',' ').replace(']',' ').replace(',',' ').split():
        if tok.startswith('#'):
            try: val=int(tok[1:],0)
            except: pass
            if val in needles:
                hits.setdefault(hex(val),[]).append({'site':hex(va),'instruction':x.mnemonic+' '+x.op_str,'function':hex(func_start(b,va) or va)})
# inspect code response references raw occurrences as LE and byte values
raw={}
for n in (0x2001,0x2002,0x200A,0x2019,0x201C,0x80000080,0x1015,0x1016):
    widths=(2,4) if n<0x10000 else (4,)
    raw[hex(n)]={}
    for w in widths:
      seq=n.to_bytes(w,'little'); poss=[]; st=0
      while True:
       i=b.data.find(seq,st)
       if i<0: break
       poss.append(hex(b.base+i));st=i+1
      raw[hex(n)][str(w)]=poss[:200]
out['immediate_hits']=hits
out['raw_hits']=raw
out['key_disasm']={hex(a):dis(b,a,50) for a in (0x2C05748,0x2C0B844,0x2C13E4C,0x2C93FD4,0x2C94A78,0x12E67AC,0x2C88E98)}
Path(__file__).with_name('первичный_поиск.json').write_text(json.dumps(out,ensure_ascii=False,indent=2)+'\n',encoding='utf8')
print('wrote',Path(__file__).with_name('первичный_поиск.json'))
print('callers',len(out['error_callers']))
print('immediate hits',{k:len(v) for k,v in hits.items()})
