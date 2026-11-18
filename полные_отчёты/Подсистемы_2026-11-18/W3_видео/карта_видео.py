from pathlib import Path
import csv, json, struct, hashlib, sys
root=Path(r'<корень проекта>\Анализ_прошивки')
sys.path.insert(0,str(root/'Сравнение_версий_2026-11-16'))
from fwcommon import load, dis
map_path=root/'Камера_2026-11-17'/'K2_прошивка'/'карта_банка.tsv'
rows=list(csv.DictReader(map_path.open(encoding='utf-8'),delimiter='\t'))
def parsehex(s): return int(s,0) if s else None
# Specific video settings, plus separate movie image-processing settings requested as *_MOVIE.
terms=('MOVIE','HS_MOVIE','HDMI_RAW','PRORES','PROXY_RECORD_MEDIA','CROP_B4','FLOGHLG')
selected={}
for r in rows:
    nm=r['name']
    relevant=nm in {'UI_SETP_MOVIE_PIXEL','UI_SETP_MOVIE_ASPECT','UI_SETP_MOVIE_FPS','UI_SETP_MOVIE_PLAY_FPS','UI_SETP_MOVIE_BITRATE','UI_SETP_MOVIE_CODEC','UI_SETP_MOVIE_FILE_FORMAT','UI_SETP_MOVIE_COMPRESSION','UI_SETP_HS_MOVIE_PIXEL','UI_SETP_HS_MOVIE_HDMIONLY_PIXEL','UI_SETP_HS_MOVIE_ASPECT','UI_SETP_HS_MOVIE_HDMIONLY_ASPECT','UI_SETP_HS_MOVIE_MODE','UI_SETP_HS_MOVIE_MODE_QMENU','UI_SETP_HS_MOVIE_FPS_REC','UI_SETP_HS_MOVIE_HDMIONLY_FPS_REC','UI_SETP_HS_MOVIE_FPS_PLAY','UI_SETP_MOVIE_4KTNR','UI_SETP_MOVIE_RECORED_MEDIA','UI_SETP_PROXY_RECORD_MEDIA','UI_SETP_PRORES_PROXY','UI_SETP_PRORES_QUALTY','UI_SETP_HDMI_RAW','UI_SETP_HDMI_RAW_SIZE_ATOMOS','UI_SETP_HDMI_RAW_SIZE_BLACKMAGIC','UI_SETP_HDMI_RAW_FPS_ATOMOS','UI_SETP_HDMI_RAW_FPS_BLACKMAGIC','UI_SETP_CROP_B4','UI_SETP_FLOGHLG_SETTING','UI_SETP_FILM_SIM_MOVIE','UI_SETP_FILM_SIM_ACROS_MOVIE','UI_SETP_FILM_SIM_MONO_MOVIE','UI_SETP_BLACK_TONE_MOVIE','UI_SETP_BLACK_TONE_RG_MOVIE','UI_SETP_DRANGE_MOVIE','UI_SETP_STILLCOLOR_MOVIE','UI_SETP_SHARPNESS_MOVIE','UI_SETP_HIGHLIGHT_MOVIE','UI_SETP_SHADOW_MOVIE','UI_SETP_NR_MOVIE','UI_SETP_MOVIE_NR','UI_SETP_CLARITY_MOVIE','UI_SETP_LEQ_MOVIE','UI_SETP_COLOR_SPACE_MOVIE'}
    if relevant and r['layout_mode']=='current' and r['selector_mode']=='0':
        selected[int(r['id'],0)]=r
# custom slot C1 map rows are numeric mode=1, slot selector 0
slot_rows={int(r['id'],0):r for r in rows if r['layout_mode']=='1' and r['selector_mode']=='1' and int(r['id'],0) in selected}
b=load('X-H2','old',1)
b0=load('X-H2','old',0)
def target(table, idx, base, first):
    delta=struct.unpack_from('<h', b.data, b.off(table)+2*idx)[0]
    return base+delta*4
settings=[]
for i,r in sorted(selected.items()):
    st=target(0x33A77E8,i-0xb,0x2c88f50,0)
    gt=target(0x33A929C,i-0xf,0x2c9403c,0)
    sr=slot_rows.get(i)
    item={'id':hex(i),'name':r['name'],'size':int(r['size']),'type':r['type'],
          'setter_branch':hex(st),'getter_branch':hex(gt),
          'translation_table':hex(0x1bd5ab8+8*i),'translation_raw_hex':b0.data[b0.off(0x1bd5ab8+8*i):b0.off(0x1bd5ab8+8*i)+8].hex(),
          'current_bank_container_offset':r['container_offset'] if r['segment'] != 'outside_exported_segments' else None,'current_bank_offset':r['bank_offset'] if r['segment'] != 'outside_exported_segments' else None,'current_segment':r['segment'],
          'custom_C1_container_offset':sr['container_offset'] if sr and sr['segment'] != 'outside_exported_segments' else None,
          'custom_C1_bank_offset':sr['bank_offset'] if sr and sr['segment'] != 'outside_exported_segments' else None,
          'custom_slot_step':'0x400' if sr else None,
          'decoder':'0x1135930; bank write 0x11335c4; bank read 0x11335ec'}
    # Actual backup blob offsets are reported with bytes only when covered by the backup.
    if sr and sr['container_offset'] and sr['segment'] != 'outside_exported_segments':
        off=parsehex(sr['container_offset'])
        vals=[]
        for label,path in [('baseline',root/'Камера_2026-11-17'/'K1_камера'/'снимки_серия'/'01_база'/'backup.bin'),
                           ('series_ES',root/'Камера_2026-11-17'/'K1_камера'/'снимки_серия'/'02_CH_ES_8000_CONT'/'backup.bin'),
                           ('series_MS',root/'Камера_2026-11-17'/'K1_камера'/'снимки_серия'/'04_MS'/'backup.bin')]:
            if path.exists():
                data=path.read_bytes(); vals.append({'sample':label,'offset':hex(off),'bytes':data[off:off+int(r['size'])].hex() if off+int(r['size'])<=len(data) else None})
        item['sample_backup_bytes']=vals
    item['confidence']='К: общая ветка и поле банка; перевод значений зависит от таблицы id'
    settings.append(item)
# Evidence summary from firmware string table for the value vocabulary.
strings=(root/'Сравнение_версий_2026-11-16'/'F_режим_съёмки'/'strings'/'XH2_5.30_b1.txt').read_text(encoding='utf-8',errors='replace').splitlines()
need=('MOVIE_RECORED_COMPRESS','PRORES_PROXY','PRORES_QUALTY','HDMI_RAW_SIZE','HDMI_RAW_FPS','HS_MOVIE','MOVIE_PIXEL','MOVIE_FPS','FLOGHLG')
value_strings=[line for line in strings if any(k in line for k in need)]
result={'firmware':'X-H2 5.30','block':'1','base':'0x29ae000','general_setter':'0x2c88e98','setter_table':'0x33a77e8','general_getter':'0x2c93fd4','getter_table':'0x33a929c','settings':settings,'string_anchors':value_strings}
out=Path(__file__).resolve().parent
(out/'результат.json').write_text(json.dumps(result,ensure_ascii=False,indent=2)+'\n',encoding='utf-8')
print('settings',len(settings),'custom',sum(x['custom_C1_bank_offset'] is not None for x in settings),'string anchors',len(value_strings))
for x in settings:
 print(x['id'],x['name'],'set',x['setter_branch'],'get',x['getter_branch'],'cur',x['current_bank_offset'],'C1',x['custom_C1_bank_offset'])




checks=[]
for x in settings:
 vals=x.get('sample_backup_bytes',[])
 checks.append((x['name'],True if x['custom_C1_bank_offset'] is None else len(vals)==3 and all(v['bytes'] is not None for v in vals) and len({v['bytes'] for v in vals})==1))
result['backup_check']={'samples':['K1/01_база','K1/02_CH_ES_8000_CONT','K1/04_MS'],'all_present_and_equal':all(ok for _,ok in checks),'checked_count':sum(1 for x in settings if x['custom_C1_bank_offset'] is not None),'outside_bank_count':sum(1 for x in settings if x['custom_C1_bank_offset'] is None),'failed':[name for name,ok in checks if not ok]}
(out/'результат.json').write_text(json.dumps(result,ensure_ascii=False,indent=2)+'\n',encoding='utf-8')
print('backup check',result['backup_check'])


