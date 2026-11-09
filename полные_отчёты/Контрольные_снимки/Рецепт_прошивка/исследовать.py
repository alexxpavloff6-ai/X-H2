"""Исследование исходных команд X-H2 5.30; снимки не открываются."""
from pathlib import Path
import hashlib, importlib.util, json, struct, sys
HERE = Path(__file__).resolve().parent
BASE = HERE.parent.parent
sys.path.insert(0, str(BASE / 'инструменты'))

def load(name, path):
    spec = importlib.util.spec_from_file_location(name, path)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module

study = load('study', BASE / 'Рецепты/Цветовые_этапы_31.10.2026/проверить_цветовые_этапы.py')
x = study.Study()
before = hashlib.sha256(x.raw).hexdigest()
# Словарные индексы из сопоставления имён; не значения EXIF.
cases = [('clarity_P3',0x605,2), ('highlight_P1p5',0x6b9,5),
         ('highlight_0',0x6b9,8), ('shadow_P0p5',0x6bb,7),
         ('shadow_0',0x6bb,8), ('WB_KELVIN',0x5f5,6),
         ('color_plus1_candidate',0x6b3,3), ('sharpness_mid_soft_candidate',0x6b5,5),
         ('NR_extra_soft_candidate',0x603,0), ('shadowing_hard_candidate',0x109,2),
         ('blue_hard_candidate',0x10a,2), ('WB_R_P1_candidate',0x6bf,8),
         ('WB_B_M5_candidate',0x6dd,14)]
converted=[]
for label, param, ui in cases:
    table=struct.unpack_from('<Q',x.a,0x1bd5ab8-0x1101000+param*8)[0]
    x.word(0x2051408,0)
    result=x.run(0x12e67ac,[param,ui,0,3]) & 0xffffffff
    error=x.u32(0x2051408)
    row=None
    if 0x1101000 <= table and table + 16*(ui+1) <= 0x1101000+len(x.a):
        row=list(struct.unpack_from('<4I',x.a,table-0x1101000+16*ui))
    converted.append({'name':label,'parameter':hex(param),'ui':ui,'table':hex(table),'row':row,'native':result,'error':error})
# Непосредственное исполнение разных тональных входов, все прочие поля равны.
# MODE 0 и 19 — синтетические; принадлежность MODE 19 к снимку не доказана.
tones=[]
p,q,o=0x60000000,0x60020000,0x60010000
for mode in [0,19]:
    x.clear(p); x.run(0x2f38c30,[p,mode]); color_mode=x.u32(p)
    for h,s in [(8,8),(11,8),(8,9),(11,9)]:
        x.clear(p);x.clear(q);x.clear(o)
        for offset,value in [(0x12c,1),(0x130,color_mode),(0x114,h),(0x118,s)]: x.word(p+offset,value)
        x.run(0x2f22acc,[p,q,o])
        tones.append({'mode_input':mode,'color_mode':color_mode,'highlight_internal':h,'shadow_internal':s,'settings_reads':list(map(hex,x.reads)),'blend':x.blends,'output':list(struct.unpack('<40H',x.uc.mem_read(o,80)))})
after=hashlib.sha256(study.base.SOURCE.read_bytes()).hexdigest()
assert before == after == study.base.EXPECTED_SHA256
result={'sha256_before':before,'sha256_after':after,'FFLZ_0x300274_sha256':hashlib.sha256(x.a).hexdigest(),'FFLZ_0x840274_sha256':hashlib.sha256(x.b).hexdigest(),'converter':'0x012e67ac 0->3','conversions':converted,'tone_function':'0x02f22acc','tone_cases':tones,'limits':'Искусственные входы, встроенный базовый образ, не аппаратная камера и не пиксели; перенос значений между отдельными вызовами выполнен исследователем.'}
(HERE/'результаты.json').write_text(json.dumps(result,ensure_ascii=False,indent=2)+'\n',encoding='utf-8')
print(json.dumps({'sha_before':before,'sha_after':after,'conversions':converted,'tones':[{'mode':v['mode_input'],'color_mode':v['color_mode'],'H':v['highlight_internal'],'S':v['shadow_internal'],'split':v['blend'][0]['split'],'output':v['output']} for v in tones]},ensure_ascii=False,indent=2))
