import sys,re,json
from pathlib import Path
sys.path.insert(0,r'<корень проекта>\Анализ_прошивки\Сравнение_версий_2026-11-16')
from fwcommon import load,bl_callers,func_start,insns
p=Path(__file__).resolve().parent
b=[load('X-H2','old',i) for i in range(3)]
def parse_int(s):
 try:return int(s,0)
 except:return None
def reg_value(lines, reg, before):
 # nearest direct assignment to source wN/xN in preceding lines; returns literal or source expression
 for ln in reversed(lines[:before]):
  m=re.search(r':\s*(mov|movz|ldr|ldrb|ldrh|ldrsw|adrp|add|sub)\s+([wx]\d+),\s*(.*)$',ln)
  if not m or m.group(2)!=reg: continue
  op,args=m.group(1),m.group(3)
  if op in ('mov','movz'):
   q=re.match(r'#(0x[0-9a-f]+|\d+)$',args)
   if q:return {'value':parse_int(q.group(1)),'expression':None}
   q=re.match(r'[wx](\d+)$',args)
   if q:return reg_value(lines,int(q.group(1)),lines.index(ln))
  return {'value':None,'expression':f'{op} {reg}, {args}'}
 return {'value':None,'expression':'incoming/unknown'}
def parse_call_context(block,site,span=0x60):
 start=max(block.base,site-span)
 ins=insns(block,start,(site-start)//4+1)
 lines=[f'{i.address:x}: {i.mnemonic} {i.op_str}' for i in ins if i.address<site]
 # latest x0 register assignment
 idv=reg_value(lines,'w0',len(lines))
 # descriptor base from last add x1,sp,#imm
 desc=None
 for idx,ln in enumerate(lines):
  m=re.search(r'add x1, sp, #(0x[0-9a-f]+|\d+)',ln)
  if m: desc=parse_int(m.group(1))
 vals=[]
 if desc is not None:
  for offset in (desc,desc+4):
   found=None
   for idx,ln in enumerate(lines):
    m=re.search(r'str w(\d+), \[sp, #(0x[0-9a-f]+|\d+)\]',ln)
    if m and parse_int(m.group(2))==offset:
     found=reg_value(lines,'w'+m.group(1),idx)
   vals.append(found or {'value':None,'expression':'not initialized in local context'})
 else: vals=[None,None]
 return {'id':idv,'descriptor_stack_offset':hex(desc) if desc is not None else None,'count':vals[0],'element_size':vals[1],'context':'\n'.join(lines[-16:])}
regs=[]
for bi in (0,1):
 for site,kind in bl_callers(b[bi],0x14CEDAC):
  fs=func_start(b[bi],site)
  q=parse_call_context(b[bi],site)
  regs.append({'block':bi,'site':hex(site),'function':hex(fs) if fs else None,**q})
# call IDs/settings from raw scanner
x=json.loads((p/'xref_api.json').read_text(encoding='utf-8'))
def static_rows(api):
 out={}
 for r in x[api]:
  if not r.get('w0'): continue
  key=int(r['w0'],16); out.setdefault(key,[]).append({'block':r['block'],'site':r['site'],'function':r['function']})
 return out
writers=static_rows('set'); readers=static_rows('get')
subs={}
for r in x['rpc']:
 if r.get('w0'):
  k=int(r['w0'],16); subs.setdefault(k,[]).append({'block':r['block'],'site':r['site'],'function':r['function'],'callback_context':r['context']})
registered={}
for r in regs:
 n=r['id']['value']
 if n is None: continue
 entry=registered.setdefault(n,{'id':hex(n),'registrations':[]})
 entry['registrations'].append(r)
for n,row in registered.items():
 row['writers']=writers.get(n,[]);row['readers']=readers.get(n,[]);row['subscribers']=subs.get(n,[])
 row['registered_count_values']=sorted(set(x['count']['value'] for x in row['registrations'] if x['count'] and x['count']['value'] is not None))
 row['registered_element_sizes']=sorted(set(x['element_size']['value'] for x in row['registrations'] if x['element_size'] and x['element_size']['value'] is not None))
 row['allocation_formula']='count × (round_up(element_size, 8) + 8)'
 row['allocated_bytes']=sorted(set(hex(c*(((v+7)&~7)+8)) for c in row['registered_count_values'] for v in row['registered_element_sizes']))
 row['registered_max_payload_sizes']=[hex(v-8) for v in row['registered_element_sizes'] if v>=8] 
 row['subsystem']='не определена, кроме записи 0x4C; принадлежность по соседнему коду требует отдельной трассировки'
 row['confidence']='Д для константных аргументов регистрации и адресов прямых вызовов; К/Г для семантики'
if 0x4c in registered:
 registered[0x4c]['subsystem']='флаг LCD / MOVDC';registered[0x4c]['known_payload_size']='0x158 (пакет публикации, не обязательно размер зарегистрированного объекта)'
jsonout={'registration_api':'block0 0x14CEDAC → service 0x4BC90 / 0x4C538','registration_calls':len(regs),'registered_static_ids':len(registered),'dynamic_registration_calls':[r for r in regs if r['id']['value'] is None],'records':[registered[n] for n in sorted(registered)],'unmatched_constant_writer_ids':[hex(n) for n in sorted(set(writers)-set(registered))],'unmatched_constant_reader_ids':[hex(n) for n in sorted(set(readers)-set(registered))],'subscriptions':[{**r,'id':r['w0']} for r in x['rpc']],'notes':['0x14CEDAC registers/initializes record objects; 0x14CF124 writes or publishes record data. Do not count them as the same operation.','Descriptor word 0 is treated as element count and word 1 as element size because 0x14CEDAC reads them at x1 and x1+4 and computes count × (round_up(size,8)+8).','For subscription IDs in RPC calls, callback pointer and ID must be read from each call context; some IDs are dynamic.']}
(p/'registered_records.json').write_text(json.dumps(jsonout,ensure_ascii=False,indent=2)+'\n',encoding='utf-8')
print('registrations',len(regs),'static ids',len(registered),'dynamic',len(jsonout['dynamic_registration_calls']))
print('unmatched writes',len(jsonout['unmatched_constant_writer_ids']),jsonout['unmatched_constant_writer_ids'])
print('unmatched reads',len(jsonout['unmatched_constant_reader_ids']),jsonout['unmatched_constant_reader_ids'])
for n,row in sorted(registered.items()):
 sz=[hex(v) for v in row['registered_element_sizes']]
 print(hex(n),'size',','.join(sz),'reg',len(row['registrations']),'writers',len(row['writers']),'readers',len(row['readers']),'subs',len(row['subscribers']))


