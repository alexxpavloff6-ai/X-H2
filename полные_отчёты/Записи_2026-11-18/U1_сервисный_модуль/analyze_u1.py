import sys
from pathlib import Path
Q=Path(r'<корень проекта>\Анализ_прошивки\Камера_2026-11-17\Q3_мост'); sys.path.insert(0,str(Q))
from q3common import loader,dis
l=loader()
out=[]
for name,va,n in [('dispatch0',0x4A458,60),('dispatch1',0x4A588,60),('dispatch2',0x4A684,60),('dispatch3',0x4A780,80),('resolve_core',0x54354,180),('record_secondary',0x546c8,160),('type0_handler',0x4b9b0,120),('type1_handler',0x4bbd4,120),('table_setup',0x45698,40),('scalar_resolve',0x50d94,70),('scalar_resolve2',0x50e64,70)]:
 out.append(f'### {name} {va:#x}\n{dis(l,va,n)}')
text='\n\n'.join(out)
Path(r'<корень проекта>\Анализ_прошивки\Записи_2026-11-18\U1_сервисный_модуль\дизассемблирование.txt').write_text(text,encoding='utf-8')
print(text)
