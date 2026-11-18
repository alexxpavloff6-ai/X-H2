import csv, json, struct
from pathlib import Path
ROOT=Path(__file__).resolve().parents[2] # .../Анализ_прошивки
K2=ROOT/'Камера_2026-11-17'/'K2_прошивка'
SNAPS=ROOT/'Камера_2026-11-17'/'K1_камера'/'снимки_серия'
OUT=Path(__file__).resolve().parent
wanted={0x827,0x858,0x859,0x864,0x866,0x89f,0x8a0,0x883,0x88f,0x898,0x755,0x5ba,0x5bc,0x5bd,0xb,0xaab,0xab8,0xabb,0xace,0xacf,0xa70,0x874,0xaaf}
rows={}
with (K2/'карта_банка.tsv').open(encoding='utf-8',newline='') as f:
    for row in csv.DictReader(f,delimiter='\t'):
        if row['layout_mode']=='current' and row['custom_slot']=='7' and row['selector_mode']=='0' and int(row['ui_setp'],16) in wanted:
            rows[int(row['ui_setp'],16)]=row

def read_val(buf,row):
    off=int(row['container_offset'],16); size=int(row['size']); typ=row['type']
    fmt={('u8',1):'<B',('u16',2):'<H',('u32',4):'<I'}.get((typ,size))
    if not fmt or off+size>len(buf): return None
    return struct.unpack_from(fmt,buf,off)[0]
res={'source':'K2 карта банка + снимки серии 17.11.2026','calibration':'Только чтение; offsets container_offset (в backup.bin)','fields':[],'snapshots':[]}
for i,row in sorted(rows.items()):
    res['fields'].append({'id':f'0x{i:X}','name':row['name'],'size':row['size'],'type':row['type'],'bank_offset':row['bank_offset'],'blob_offset':row['blob_offset'],'container_offset':row['container_offset']})
for d in sorted(SNAPS.iterdir()):
    p=d/'backup.bin'
    if not d.is_dir() or not p.exists(): continue
    buf=p.read_bytes(); ent={'snapshot':d.name,'bytes':len(buf),'values':{}}
    for i,row in sorted(rows.items()): ent['values'][row['name']]=read_val(buf,row)
    res['snapshots'].append(ent)
(OUT/'сверка_снимков.json').write_text(json.dumps(res,ensure_ascii=False,indent=2)+'\n',encoding='utf-8')
print(f'fields={len(rows)}, snapshots={len(res["snapshots"])} -> сверка_снимков.json')
for ent in res['snapshots']:
    vals=ent['values']
    if ent['snapshot'] in ['01_база','02_CH_ES_8000_CONT','02B_CH_MSES_16000_CONT_успех','02C_CH_ES_8000_CONT','03_S','04_MS_CH','05_1-250','06_DISP_OFF','07C_база_повтор']:
        print(ent['snapshot'], {k: vals.get(k) for k in ['UI_SETP_SHUTTER_TYPE','UI_SETP_CONTINUOUS','UI_SETP_SHUTTER_SPEED_M','UI_SETP_DOTLCD_SHUTTERTYPE_OUTPUT','UI_SETP_DOTLCD_SHUTERSPEED_OUTPUT','UI_SETP_DOTLCD_CONTINUOUS','UI_SETP_REC_VIEW']})
