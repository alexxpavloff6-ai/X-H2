"""Продолжение AF: синтетическая VM и статический поиск в двух FFLZ каждой модели."""
from pathlib import Path
import hashlib, importlib.util, json, struct, sys
from capstone import Cs, CS_ARCH_ARM64, CS_MODE_ARM
from unicorn import Uc, UcError, UC_ARCH_ARM64, UC_MODE_ARM, UC_HOOK_CODE, UC_HOOK_MEM_INVALID, UC_HOOK_MEM_WRITE
from unicorn import arm64_const as R
HERE = Path(__file__).resolve().parent
AN = HERE.parents[1]; ROOT = AN.parent
sys.path.insert(0, str(AN / 'инструменты'))
spec = importlib.util.spec_from_file_location('prev', AN / 'Последовательное_исследование/Этап_5/Автофокус/исследовать.py')
prev = importlib.util.module_from_spec(spec); spec.loader.exec_module(prev)
cs = Cs(CS_ARCH_ARM64, CS_MODE_ARM)
def h(x): return hex(x)
def main():
 out = {}
 for name,c in prev.CONFIG.items():
  path,expected,offsets,handler,wrapper,lookup,norm,classify,ptr,u16,slot,threshold,table,values=c
  source=ROOT/path; raw=source.read_bytes(); before=hashlib.sha256(raw).hexdigest()
  if before!=expected: raise ValueError(name+' hash')
  decoded=raw.translate(prev.base.TRANSLATION); blocks=[]
  for off in offsets:
   b=prev.base.unpack_fflz(decoded,off); blocks.append((struct.unpack_from('<Q',b,8)[0],b,off))
  def orig(addr,n):
   for base,b,_ in blocks:
    if base<=addr and addr+n<=base+len(b): return b[addr-base:addr-base+n]
   raise ValueError(h(addr))
  def dis(addr,n):
   return [{'pc':h(x.address),'bytes':bytes(x.bytes).hex(),'ins':x.mnemonic+' '+x.op_str} for x in cs.disasm(orig(addr,n),addr)]
  boundary=handler+0x58
  accessor=int(dis(boundary,4)[0]['ins'].split('#')[1],16)
  reader=int(dis(accessor+8,4)[0]['ins'].split('#')[1],16)
  refs=[]; callers=[]; immediate_sites=[]; caller_counts={h(accessor):0,h(reader):0}
  for base,b,off in blocks:
   for pos in range(0,len(b)-64,4):
    w=struct.unpack_from('<I',b,pos)[0]; pc=base+pos
    if w>>26==0x25:
     imm=w&0x3ffffff; imm=imm-(1<<26) if imm&(1<<25) else imm
     target=pc+(imm<<2)
     if target in (accessor,reader):
      caller_counts[h(target)]+=1
      if pos>=8 and b[pos-8:pos]==bytes.fromhex('a00180522000a072'):
       callers.append({'pc':h(pc),'target':h(target),'instructions':dis(pc-8,16)})
    if w==0x528001a0 and b[pos+4:pos+8]==bytes.fromhex('2000a072'):
     immediate_sites.append({'pc':h(pc),'instructions':dis(pc,32)})
    if w&0x9f000000 != 0x90000000: continue
    imm=((w>>29)&3)|(((w>>5)&0x7ffff)<<2)
    if imm&(1<<20): imm-=1<<21
    if (pc&~0xfff)+(imm<<12)!=(slot&~0xfff): continue
    reg=w&31
    for j in range(1,9):
     v=struct.unpack_from('<I',b,pos+4*j)[0]
     if ((v&0xffc00000) in (0xf9400000,0xf9000000) and ((v>>5)&31)==reg and ((v>>10)&0xfff)*8==(slot&0xfff)) or ((v&0xffc00000)==0x91000000 and ((v>>5)&31)==reg and ((v>>10)&0xfff)==(slot&0xfff)):
      refs.append({'adrp':h(pc),'use':h(pc+4*j),'instructions':dis(pc,4*(j+1))})
  runs=[]
  state_addr={'X-H2 5.30':0x261a954,'X-H2S 7.30':0x2936954,'X-T5 4.31':0x256e754}.get(name)
  status_entry={'X-H2 5.30':0x13f5c08,'X-H2S 7.30':0x1713d50,'X-T5 4.31':0x13f40d8,'X100VI 1.31':0x1608060}[name]
  extra=[('state2_further',0,False,0),('state_unmapped_further',0,False,0)] if state_addr else []
  for label,byte,missing,index in [('zero',0,False,0x10203040),('one',1,False,0x10203040),('high',128,False,0x10203040),('unmapped_flag',0,True,0x10203040),('zero_index0',0,False,0),('one_index0',1,False,0),('zero_index1',0,False,1),('one_index1',1,False,1),('zero_index0_extended',0,False,0),('one_index0_extended',1,False,0),('zero_index1_extended',0,False,1),('one_index1_extended',1,False,1),('zero_index0_deep',0,False,0),('one_index0_deep',1,False,0),('zero_index1_deep',0,False,1),('one_index1_deep',1,False,1),('zero_key0_further',0,False,0),('one_key0_further',1,False,0),('zero_key1_further',0,False,1),('one_key1_further',1,False,1)]+extra:
   u=Uc(UC_ARCH_ARM64,UC_MODE_ARM); u.mem_map(0x1000,0x6000000-0x1000)
   for base,b,_ in blocks: u.mem_write(base,b)
   u.mem_map(0x70000000,0x100000); u.mem_map(0x71000000,0x800000)
   u.reg_write(R.UC_ARM64_REG_SP,0x700ff000); u.reg_write(R.UC_ARM64_REG_X0,0x70002000); u.reg_write(R.UC_ARM64_REG_X30,0x500)
   u.mem_write(0x70002000,struct.pack('<QQQ',0x70001000,0x70010000,0x70030000))
   key=(1 if 'key1' in label else 0) if label.endswith('_further') else 0x89abcdef
   for addr,val in [(0x70001000,key),(0x70001018,2),(0x70001020,4),(0x70001040,index),(threshold,16)]: u.mem_write(addr,struct.pack('<I',val))
   u.mem_write(slot,struct.pack('<Q',0x71000000)); u.mem_write(0x71000000+table+2*31+4,b'\x03'); u.mem_write(0x71000000+values+6,struct.pack('<H',0x1234)); u.mem_write(0x7101000d,bytes([byte]))
   if missing: u.mem_unmap(0x71010000,0x1000)
   if label=='state2_further': u.mem_write(state_addr,struct.pack('<I',2))
   if label=='state_unmapped_further': u.mem_unmap(state_addr & ~0xfff,0x1000)
   run={'case':label,'flag':None if missing else byte,'synthetic_field_0':h(key),'synthetic_field_40':h(index),'calls':[],'writes':[],'status_returns':[],'last':[],'count':0}; state={'active':False}
   def code(uc,pc,size,user):
    run['count']+=1
    if pc==boundary+4: state['active']=True; run['flag_return']=h(uc.reg_read(R.UC_ARM64_REG_W0))
    if not state['active']: return
    if pc==status_entry+(8 if state_addr else 4):
     run['status_returns'].append({'pc':h(pc),'w0':h(uc.reg_read(R.UC_ARM64_REG_W0))})
    ins=next(cs.disasm(bytes(uc.mem_read(pc,4)),pc),None)
    if ins is None: run['stop']='undecodable'; uc.emu_stop(); return
    rec={'pc':h(pc),'bytes':bytes(ins.bytes).hex(),'ins':ins.mnemonic+' '+ins.op_str}
    run['last'].append(rec); run['last']=run['last'][-20:]
    if ins.mnemonic in ('bl','blr'):
     rec=dict(rec); rec['x0']=h(uc.reg_read(R.UC_ARM64_REG_X0)); rec['x1']=h(uc.reg_read(R.UC_ARM64_REG_X1)); rec['x2']=h(uc.reg_read(R.UC_ARM64_REG_X2)); run['calls'].append(rec)
     limit=20000 if label.endswith('_further') else 3000 if label.endswith('_deep') else 300 if label.endswith('_extended') else 40
     if len(run['calls'])>=limit: run['stop']=f'before call {limit}'; uc.emu_stop()
    if pc==0x500: run['stop']='returned'; uc.emu_stop()
   def invalid(uc,access,address,size,value,user): run['invalid']={'pc':h(uc.reg_read(R.UC_ARM64_REG_PC)),'address':h(address),'size':size,'access':access}; return False
   def write(uc,access,address,size,value,user):
    if state['active'] and 0x70010000<=address<0x70010100 and len(run['writes'])<100: run['writes'].append({'pc':h(uc.reg_read(R.UC_ARM64_REG_PC)),'address':h(address),'size':size,'value':h(value)})
   u.hook_add(UC_HOOK_CODE,code); u.hook_add(UC_HOOK_MEM_INVALID,invalid); u.hook_add(UC_HOOK_MEM_WRITE,write)
   budget=1000000 if label.endswith('_further') else 200000 if label.endswith('_deep') else 20000
   try: u.emu_start(handler,0x500,count=budget)
   except UcError as e: run['error']=str(e)
   if 'stop' not in run and 'error' not in run:
    run['stop']='returned' if u.reg_read(R.UC_ARM64_REG_PC)==0x500 else f'instruction budget {budget}'
   run['final_w0']=h(u.reg_read(R.UC_ARM64_REG_W0))
   run['output_prefix_100']=bytes(u.mem_read(0x70010000,0x100)).hex()
   runs.append(run)
  writer_adrp=int(refs[1]['adrp'],16); writer=writer_adrp-16
  writer_runs=[]
  for logical,value,missing in [(0x1000d,0x1ab,False),(0x1000e,0x1ab,False),(0x1000d,0x1ab,True)]:
   u=Uc(UC_ARCH_ARM64,UC_MODE_ARM); u.mem_map(0x1000,0x6000000-0x1000)
   for base,b,_ in blocks: u.mem_write(base,b)
   u.mem_map(0x70000000,0x10000)
   if not missing: u.mem_map(0x71000000,0x20000)
   u.mem_write(slot,struct.pack('<Q',0x71000000)); u.reg_write(R.UC_ARM64_REG_SP,0x7000f000)
   u.reg_write(R.UC_ARM64_REG_X0,logical); u.reg_write(R.UC_ARM64_REG_X1,value); u.reg_write(R.UC_ARM64_REG_X30,0x500)
   wr={'logical':h(logical),'value':h(value),'unmapped':missing,'trace':[]}
   def trace(uc,pc,size,user):
    if pc==0x500: uc.emu_stop(); return
    x=next(cs.disasm(bytes(uc.mem_read(pc,4)),pc))
    wr['trace'].append({'pc':h(pc),'bytes':bytes(x.bytes).hex(),'ins':x.mnemonic+' '+x.op_str})
   def fault(uc,access,address,size,value,user):
    wr['invalid']={'pc':h(uc.reg_read(R.UC_ARM64_REG_PC)),'address':h(address),'size':size,'access':access}; return False
   u.hook_add(UC_HOOK_CODE,trace); u.hook_add(UC_HOOK_MEM_INVALID,fault)
   try: u.emu_start(writer,0x500,count=200)
   except UcError as e: wr['error']=str(e)
   if not missing:
    wr['bytes_at_1000d_1000e']=bytes(u.mem_read(0x7101000d,2)).hex()
    u.reg_write(R.UC_ARM64_REG_X0,0x1000d); u.reg_write(R.UC_ARM64_REG_X30,0x500)
    u.emu_start(reader,0x500,count=200)
    wr['reader_result']=h(u.reg_read(R.UC_ARM64_REG_W0))
   writer_runs.append(wr)
  after=hashlib.sha256(source.read_bytes()).hexdigest()
  if before!=after: raise ValueError(name+' changed')
  out[name]={'source':path,'sha256_before':before,'sha256_after':after,'blocks':[{'base':h(a),'length':len(b),'offset_dat':h(off),'sha256':hashlib.sha256(b).hexdigest()} for a,b,off in blocks], 'handler':h(handler),'slot':h(slot),'byte_accessor':h(accessor),'byte_reader':h(reader),'byte_writer':h(writer),'writer_runs':writer_runs,'status_global':h(state_addr) if state_addr else None,'status_code':dis(status_entry,12 if state_addr else 8),'slot_candidates':refs,'slot_windows':[dis(int(q['adrp'],16),64) for q in refs], 'caller_counts':caller_counts,'direct_callers_1000d':callers,'immediate_1000d_sites':immediate_sites,'runs':runs}
  print(name,[(r['case'],r.get('invalid'),r.get('stop'),len(r['calls'])) for r in runs],flush=True)
 (HERE/'результаты.json').write_text(json.dumps(out,ensure_ascii=False,indent=2),encoding='utf-8')
if __name__=='__main__': main()
