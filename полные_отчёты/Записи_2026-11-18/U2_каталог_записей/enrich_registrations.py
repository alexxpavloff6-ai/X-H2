import json,re
from pathlib import Path
p=Path(__file__).resolve().parent
x=json.loads((p/'xref_api.json').read_text(encoding='utf-8'))
r=json.loads((p/'registered_records.json').read_text(encoding='utf-8'))
def num(v):
 try:return int(v,0)
 except:return None
def callback(ctx):
 lines=ctx.splitlines()
 # resolve ADRP+ADD materialization when x2 is a direct code address
 if any('ldr x2, [' in line for line in lines):
  loadline=next(line for line in reversed(lines) if 'ldr x2, [' in line)
  return {'address':None,'kind':'loaded_from_table_or_memory','expression':loadline.split(': ',1)[-1]}
 for i in range(len(lines)-1,-1,-1):
  m=re.search(r'add x2, x2, #(0x[0-9a-f]+|\d+)',lines[i])
  if not m: continue
  off=num(m.group(1))
  for prev in reversed(lines[:i]):
   a=re.search(r'adrp x2, #(0x[0-9a-f]+|\d+)',prev)
   if a:return {'address':hex(num(a.group(1))+off),'kind':'direct'}
  return {'address':None,'kind':'unresolved_add'}
 for line in reversed(lines):
  if re.search(r'ldr x2, \[',line):return {'address':None,'kind':'loaded_from_table_or_memory','expression':line.split(': ',1)[-1]}
  if re.search(r'mov x2, ',line):return {'address':None,'kind':'register_value','expression':line.split(': ',1)[-1]}
 return {'address':None,'kind':'not_resolved'}
rpc=[]
for row in x['rpc']:
 rpc.append({'id':row.get('w0'),'id_static':row.get('w0') is not None,'block':row['block'],'site':row['site'],'calling_function':row['function'],'callback':callback(row['context']),'context':row['context']})
r['subscriptions']=rpc
r['subscription_ids_static']=sorted(set(q['id'] for q in rpc if q['id_static']))
r['subscription_only_ids']=[q for q in r['subscription_ids_static'] if q not in {e['id'] for e in r['records']}]
r['registration_vs_subscription_conclusion']='Для статических ID ни один из трёх ID RPC-подписок (0x6, 0x1E, 0x3E8) не совпал с ID, зарегистрированными через 0x14CEDAC; поэтому их оставляем отдельными подписками, не приписывая к записи без доказательства.'
(p/'registered_records.json').write_text(json.dumps(r,ensure_ascii=False,indent=2)+'\n',encoding='utf-8')
f=p/'результат.json'; j=json.loads(f.read_text(encoding='utf-8'))
j['registrations']={'api':'0x14CEDAC в блоках 0–1 → сервисные вызовы 0x4BC90 и 0x4C538','direct_calls':r['registration_calls'],'static_unique_ids':r['registered_static_ids'],'dynamic_registration_calls':r['dynamic_registration_calls'],'records':r['records'],'unmatched_constant_writer_ids':r['unmatched_constant_writer_ids'],'unmatched_constant_reader_ids':r['unmatched_constant_reader_ids']}
j['rpc_subscriptions']={'api':'0x14CF45C','calls':len(rpc),'entries':rpc,'subscription_only_ids':r['subscription_only_ids'],'note':r['registration_vs_subscription_conclusion']}
# Единую таблицу строим из регистраций, прямых чтений/записей и статических RPC-ID.
raw_records={e['id']:e for e in r['records']}
old_records={e['id']:e for e in j.get('records',[])}
ids=set(raw_records)|set(old_records)|set(q['id'] for q in rpc if q['id_static'])
unified=[]
for ident in sorted(ids,key=lambda x:int(x,16)):
 reg=raw_records.get(ident); old=old_records.get(ident)
 writers=(reg or {}).get('writers',[]) or (old or {}).get('writers',[])
 readers=(reg or {}).get('readers',[]) or (old or {}).get('readers',[])
 subscribers=[{'block':q['block'],'site':q['site'],'function':q['calling_function'],'callback':q['callback']} for q in rpc if q.get('id')==ident]
 registration=None
 if reg:
  slot_sizes=reg['registered_element_sizes']
  payload_caps=[hex(v-8) for v in slot_sizes if v>=8]
  registration={'registration_calls':reg['registrations'],'count_values':reg['registered_count_values'],'slot_sizes':[hex(v) for v in slot_sizes],'max_payload_sizes':payload_caps,'allocated_bytes':reg['allocated_bytes'],'allocation_formula':reg['allocation_formula']}
  state='зарегистрирована с постоянным ID'
 elif subscribers and not writers and not readers:
  state='только RPC-подписка; соответствующая регистрация с постоянным ID не найдена'
 else:
  state='прямая операция с постоянным ID; регистрация не найдена среди константных вызовов (возможен динамический путь)'
 entry={'id':ident,'registration_status':state,'registration':registration,'writers':[{'block':a['block'],'site':a['site'],'function':a['function']} for a in writers],'readers':[{'block':a['block'],'site':a['site'],'function':a['function']} for a in readers],'subscribers':subscribers,'subsystem':'не установлена'}
 if ident=='0x4c':
  entry['registration']['max_payload_sizes']=['0x158']
  entry['subsystem']='передача LCD-флага в MOVDC'
  entry['fields']={'payload+0x64':'флаг LCD-защиты'}
  entry['known_publication']={'writer_function':'0x311B6B8','write_call':'0x311B788','payload_size':'0x158','reader_function':'0x3105390','read_call':'0x31053F8','consumer':'MOVDC 0x3103FF8'}
  entry['confidence']='Д'
 unified.append(entry)
j['records']=unified
j['record_count_unified']=len(unified)
j['registration_vs_subscription_note']=r['registration_vs_subscription_conclusion']
j['limitations']=['15 регистраций и 7 RPC-подписок имеют вычисляемые ID; восемь прямых записей и одно чтение с константным ID не сопоставлены с константной регистрацией.','Подсистема назначена только для 0x4C; назначение остальных записей требует трассировки полей/потребителей.','Размер слота регистрации и максимум данных публикации различаются на 8 байт; размеры коротких слотов <8 не интерпретируются как предел публикации.']
f.write_text(json.dumps(j,ensure_ascii=False,indent=2)+'\n',encoding='utf-8')
print('unified records',len(unified),'registered',sum(e['registration'] is not None for e in unified),'subscription-only',len(r['subscription_only_ids']))
