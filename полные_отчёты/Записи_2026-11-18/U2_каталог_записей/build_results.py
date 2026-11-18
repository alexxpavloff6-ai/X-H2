import json,re
from pathlib import Path
p=Path(__file__).resolve().parent
x=json.loads((p/'xref_api.json').read_text(encoding='utf-8'))
def parse_id(r):
 return int(r['w0'],16) if r.get('w0') else None
def parse_size(r):
 lines=r['context'].splitlines(); ptr=None
 for ln in lines:
  m=re.search(r'add x1, sp, #(0x[0-9a-f]+|\d+)',ln)
  if m: ptr=int(m.group(1),0)
 if ptr is None:return None
 target=ptr+4
 for i,ln in enumerate(lines):
  m=re.search(r'str w0, \[sp, #(0x[0-9a-f]+|\d+)\]',ln)
  if m and int(m.group(1),0)==target and i:
   prev=lines[i-1]
   q=re.search(r'mov(?:z)? w0, #(0x[0-9a-f]+|\d+)',prev)
   if q:return int(q.group(1),0)
 return None
writes={}; reads={}; dynamic={'set':[],'get':[]}
for api,dest in [('set',writes),('get',reads)]:
 for r in x[api]:
  ident=parse_id(r)
  if ident is None:
   dynamic[api].append({'block':r['block'],'site':r['site'],'function':r['function']});continue
  row=dest.setdefault(ident,{'id':hex(ident),'writers':[],'readers':[],'sizes':[]})
  item={'block':r['block'],'site':r['site'],'function':r['function']}
  if api=='set':
   row['writers'].append(item); z=parse_size(r)
   if z is not None:row['sizes'].append(z)
  else:row['readers'].append(item)
# join into a single record catalog
allids=sorted(set(writes)|set(reads))
records=[]
for n in allids:
 w=writes.get(n,{});r=reads.get(n,{})
 records.append({'id':hex(n),'writers':w.get('writers',[]),'readers':r.get('readers',[]),'observed_payload_sizes':sorted(set(w.get('sizes',[]))),'subsystem':'не установлена без трассировки данных записи к функциям-потребителям','confidence':'К для прямых ссылок; Г для назначения'})
result={'firmware':'X-H2 5.30','method':'статический поиск прямых BL к API по блокам 0–2; ID извлечён только при видимой константе w0 в ближайшем контексте, размер — только при видимом поле дескриптора. Динамические ID перечислены отдельно.','api_counts':{name:{'direct_calls':len(x[name]),'by_block':{str(i):sum(r['block']==i for r in x[name]) for i in range(3)}} for name in ('set','get','scalar','rpc')},'direct_constant_ids':{'set':sorted(hex(k) for k in writes),'get':sorted(hex(k) for k in reads)},'dynamic_id_calls':dynamic,'records':records,'known_chains':[{'id':'0x4c','writer':'0x311B6B8 → 0x14CF124','payload_size':'0x158','reader':'0x31053F8 → 0x14CF354','consumer':'MOVDC 0x3103FF8','subsystem':'MOVDC/состояние дисплея; в payload +0x64 находится флаг LCD-защиты','confidence':'Д по цепочке до MOVDC; размер 0x158 и писатель подтверждены кодом'}, {'id':'0x2','writer_functions':[r['function'] for r in writes.get(2,{}).get('writers',[])],'payload_sizes':sorted(set(writes.get(2,{}).get('sizes',[]))),'reader_functions':[r['function'] for r in reads.get(2,{}).get('readers',[])],'subsystem':'съёмочный тракт блока 1; конкретный потребитель/семантика поля не установлены','confidence':'К по расположению; назначение записи не доказано'}], 'focus_settings_review':{'settings':['0x8C0','0x6FB','0x620','0x618','0x61C','0x70D','0x710–0x723','0x1E2','0x5BA–0x5BE'],'result':'совпадения функций прямых API записи/чтения с AF-обработчиками и прямыми читателями этих UI_SETP не найдено в проверенных путях блоков 0–2','boundary':'не исключены непрозрачные поля пакета 0x4C или код вне блоков/вне установленного сервисного модуля','confidence':'Д для отсутствия прямого вызова/пересечения; Г для отсутствия любого косвенного канала'}, 'limitations':['Размеры пакетов всех записей нельзя надёжно получить из аргументов API чтения: размер разрешается через реестр сервисного модуля.','Часть ID задаётся данными таблиц/регистров, а не константой; см. dynamic_id_calls.','Прямой BL и ближайшая функция не всегда равны фактическому семантическому писателю: передача может идти через общий построитель/обёртку.']}
(p/'результат.json').write_text(json.dumps(result,ensure_ascii=False,indent=2)+'\n',encoding='utf-8')
print('records',len(records),'constant set ids',len(writes),'get ids',len(reads),'dynamic set/get',len(dynamic['set']),len(dynamic['get']))
for rec in records:
 if rec['id'] in ('0x4c','0x2','0x4f','0x88','0x8b','0x3','0x4e'):
  print(rec['id'],'writers',len(rec['writers']),'readers',len(rec['readers']),'sizes',[hex(z) for z in rec['observed_payload_sizes']])
