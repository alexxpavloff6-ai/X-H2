import sys, csv, struct, re
from pathlib import Path
root=Path(r'<корень проекта>\Анализ_прошивки')
sys.path.insert(0,str(root/'Сравнение_версий_2026-11-16'))
from fwcommon import *
rows=list(csv.DictReader((root/'Камера_2026-11-17'/'K2_прошивка'/'карта_банка.tsv').open(encoding='utf-8'),delimiter='\t'))
names=['MOVIE_FILE_FORMAT','MOVIE_PIXEL','MOVIE_ASPECT','MOVIE_FPS','MOVIE_PLAY_FPS','PRORES_QUALTY','PRORES_PROXY','PROXY_RECORD_MEDIA','MOVIE_RECORED_MEDIA','HDMI_RAW','HS_MOVIE','CROP_B4','FLOGHLG','MOVIE_4KTNR']
sel=[r for r in rows if r['layout_mode']=='current' and r['selector_mode']=='0' and any(n in r['name'] for n in names)]
b=load('X-H2','old',1)
def dispatch(table,index,adrbase):
    off=struct.unpack_from('<h',b.data,b.off(table)+index*2)[0]
    return adrbase+off*4
print('settings',len(sel))
for r in sel:
    i=int(r['id'],0); name=r['name']; set_t=dispatch(0x33A77E8,i-0xB,0x2C88F50); get_t=dispatch(0x33A929C,i-0xF,0x2C9403C)
    print(f"{i:#05x} {name:48} bank={r['container_offset']} size={r['size']} type={r['type']} set={set_t:#x} get={get_t:#x}")
    print(' S:',dis(b,set_t,18).replace('\n',' | '))
    print(' G:',dis(b,get_t,12).replace('\n',' | '))


