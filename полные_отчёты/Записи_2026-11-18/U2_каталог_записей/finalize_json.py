import json
from pathlib import Path
p=Path(__file__).resolve().parent
f=p/'результат.json'; j=json.loads(f.read_text(encoding='utf-8'))
for r in j['records']:
 r['observed_call_payload_sizes']=r.pop('observed_payload_sizes',[])
 r['confidence']='Д для прямых ссылок; Г для назначения записи'
j['limitations'][0]='Размер полного объекта записи разрешается через реестр сервисного модуля. Числа в observed_call_payload_sizes — только размеры отдельных передаваемых дескрипторов там, где их удалось прочитать из кода; это не доказанный размер объекта записи.'
r4c=next(r for r in j['records'] if r['id']=='0x4c')
r4c.update({'record_object_size':'0x158','subsystem':'путь записи LCD-флага в MOVDC','fields':{'payload+0x64':'флаг LCD-защиты'},'consumer':'MOVDC 0x3103FF8','confidence':'Д'})
j['focus_settings_review']['observed_no_record_api_functions']=['0x1338C70','0x1338C9C','0x1338CC8','0x12F0BD4','0x12F0C6C','0x12F0D04']
j['focus_settings_review']['local_destinations']=['0x2680474','0x2680478','0x268047C']
f.write_text(json.dumps(j,ensure_ascii=False,indent=2)+'\n',encoding='utf-8')
