import sys
from pathlib import Path
Q=Path(r'<корень проекта>\Анализ_прошивки\Камера_2026-11-17\Q3_мост'); sys.path.insert(0,str(Q))
from q3common import load,insns,bl_callers,func_start
out=[]
for idx in (0,1):
 b=load('X-H2','old',idx)
 for target in (0x14CF124,0x14CF354,0x14CF45C,0x14CF404):
  calls=bl_callers(b,target); out.append(f'### b{idx} {target:#x}: {len(calls)}')
  for site,k in calls:
   fs=func_start(b,site) or site-0x30
   lines=insns(b,max(fs,site-0x40),min(24,(site-max(fs,site-0x40))//4+1))
   out.append(f'-- call {site:#x} func {fs:#x}')
   out.extend(f'{x.address:x}: {x.mnemonic} {x.op_str}' for x in lines)
text='\n'.join(out)
Path(r'<корень проекта>\Анализ_прошивки\Записи_2026-11-18\U1_сервисный_модуль\api_calls.txt').write_text(text,encoding='utf-8')
print('saved',len(text),'bytes; total',sum(len(bl_callers(load('X-H2','old',i),t)) for i in (0,1) for t in (0x14CF124,0x14CF354,0x14CF45C,0x14CF404)))
