import sys
sys.path.insert(0,r'<корень проекта>\Анализ_прошивки\Сравнение_версий_2026-11-16')
from fwcommon import load,adrp_sites,dis
b=load('X-H2','old',1)
for page in [0x26bd000,0x26be000,0x26bf000,0x26c0000,0x26c1000]:
 refs=adrp_sites(b,page);print('\nPAGE',hex(page),'n',len(refs))
 for va,r in refs[:20]:print(hex(va),f'x{r}',dis(b,va,12))
