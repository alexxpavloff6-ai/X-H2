from __future__ import annotations
import json, sys
from pathlib import Path
HERE=Path(__file__).resolve().parent
ANALYSIS=HERE.parents[1]
sys.path.insert(0,str(ANALYSIS/'Сравнение_версий_2026-11-16'))
sys.path.insert(0,str(ANALYSIS/'Сравнение_версий_2026-11-16'/'B_объектив_0x411'))
from fwcommon import load,func_start
from scan import find_imm12
from capstone import Cs,CS_ARCH_ARM64,CS_MODE_LITTLE_ENDIAN
cs=Cs(CS_ARCH_ARM64,CS_MODE_LITTLE_ENDIAN)

out={'константа':'0x411','блоки':{}}
for idx in (0,1):
  for state in ('old','new'):
    b=load('X-H2',state,idx)
    sites=find_imm12(b,0x411)
    starts={func_start(b,site) for site in sites}
    caller_map={s:[] for s in starts if s is not None}
    # One pass over the block for all direct callers, rather than rescanning it for each site.
    for va in range(b.base,b.end-3,4):
      word=b.u32(va)
      if (word & 0x7c000000)==0x14000000:
        imm=word & 0x3ffffff
        if imm & (1<<25): imm-=1<<26
        target=va+imm*4
        if target in caller_map:
          caller_map[target].append({'сайт':hex(va),'тип':'bl' if word & 0x80000000 else 'b'})
    rows=[]
    for site in sites:
      start=func_start(b,site)
      # Include 3 instructions before and 4 after to show the operand and branch.
      lo=max(b.base,site-12)
      hi=min(b.end,site+20)
      window=[{'адрес':hex(i.address),'инструкция':i.mnemonic+' '+i.op_str} for i in cs.disasm(b.data[b.off(lo):b.off(hi)],lo)]
      callers=caller_map.get(start,[])
      rows.append({'сайт':hex(site),'функция':hex(start) if start else None,'сравниваемый_регистр':cs.disasm(b.data[b.off(site):b.off(site)+4],site).__next__().op_str.split(',')[0].replace('cmp ','') if True else None,'окно':window,'прямые_вызывающие':callers})
    out['блоки'][f'X-H2 {b.version} b{idx}']={'количество':len(rows),'сравнения':rows}
(HERE/'lens_id_0x411.json').write_text(json.dumps(out,ensure_ascii=False,indent=2)+'\n',encoding='utf-8')
for k,v in out['блоки'].items():
  print(k,v['количество'])
  for r in v['сравнения']:
    print(' ',r['сайт'],'fn',r['функция'],'op',r['сравниваемый_регистр'],'callers',','.join(x['сайт'] for x in r['прямые_вызывающие']))
