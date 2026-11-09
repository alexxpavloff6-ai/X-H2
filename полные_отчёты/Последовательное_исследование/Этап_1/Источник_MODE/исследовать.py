from pathlib import Path
import hashlib, importlib.util, json, struct, sys
sys.dont_write_bytecode = True
HERE = Path(__file__).resolve().parent
AN = HERE.parents[2]
ROOT = AN.parent
sys.path.insert(0, str(AN / 'инструменты'))
spec = importlib.util.spec_from_file_location('firmware', AN / 'анализ_файла.py')
base = importlib.util.module_from_spec(spec); spec.loader.exec_module(base)
from capstone import Cs, CS_ARCH_ARM64, CS_MODE_LITTLE_ENDIAN
from capstone.arm64 import ARM64_OP_REG, ARM64_OP_IMM, ARM64_OP_MEM
from unicorn import Uc, UC_ARCH_ARM64, UC_MODE_ARM, UC_HOOK_MEM_READ, UC_HOOK_MEM_WRITE
from unicorn.arm64_const import UC_ARM64_REG_X0, UC_ARM64_REG_X1, UC_ARM64_REG_X2, UC_ARM64_REG_X3, UC_ARM64_REG_X30, UC_ARM64_REG_SP, UC_ARM64_REG_PC
C = Cs(CS_ARCH_ARM64, CS_MODE_LITTLE_ENDIAN); C.detail = True
MODELS = [
 ('X-H2','FIRMWARE/ver 5.30/FWUP0028.DAT','be47168cb075ef726e67cb4bb08175a896047a3b0de2bcb6e65333b22cfcb203',[0x300274,0x840274],[0x1101000,0x29ae000],0x4d23732,0x2680414),
 ('X-H2S','Firmware на прочиеFuji/FWUP0027.DAT','87c566c1ff6343e4c7463a4ef968183f41d1f24cc63d610433d3a387b13f731b',[0x300274,0x840274],[0x1421000,0x2cca000],0x4c970f2,0x299c40c),
 ('X-T5','Firmware на прочиеFuji/FWUP0030.DAT','790d6deecf26766188b0e506e40645e6b816addfeba39a52334349405421724e',[0x300274,0x820274],[0x1101000,0x28eb000],0x4bab8b6,0x25bcccc),
 ('X100VI','Firmware на прочиеFuji/FPUPDATE.DAT','0d48d2ae26ac7ebab9b0e4cac56324807ec1ea8ae30df06b0b9e79066dc0a14a',[0x9c02bc,0x10e02bc],[0x11c1000,0x2b8f000],0x52b761e,0x27f7a54)]
FUNCS={'X-H2':(0x2fbf82c,0x2fbf7c8,0x15ebe80,0x2cc,0x26a),'X-H2S':(0x32d5098,0x32d5034,0x190b780,0x2cc,0x26a),'X-T5':(0x2efbd0c,0x2efbca8,0x15e24c0,0x2c8,0x266),'X100VI':(0x31ddda4,0x31ddd40,0x16bd380,0x2c8,0x266)}
WRAPPERS={'X-H2':(0x2fbfab4,0x2fc0720,0x2fc0734),'X-H2S':(0x32d5320,0x32d5f8c,0x32d5fa0),'X-T5':(0x2efbf84,0x2efcbb8,0x2efcbcc),'X100VI':(0x31de01c,0x31dec98,0x31decac)}
def ins(i): return {'address':hex(i.address),'bytes':i.bytes.hex(),'instruction':i.mnemonic+' '+i.op_str}
def reg(i, n):
 s=i.reg_name(n)
 return 'x'+s[1:] if s.startswith('w') and s[1:].isdigit() else s

def scan(data, addr, target):
 # ADRP into either adjacent page; forward-slice a bounded linear instruction window.
 pages={((target+d)&~0xfff) for d in (-0x1000,0,0x1000)}
 hits=[]; pointers=[]; adrp_count=0
 for off in range(0,len(data)-4,4):
  word=struct.unpack_from('<I',data,off)[0]
  if word & 0x9f000000 != 0x90000000: continue
  imm=((word>>29)&3)|(((word>>5)&0x7ffff)<<2)
  if imm & (1<<20): imm-=1<<21
  page=((addr+off)&~0xfff)+(imm<<12)
  if page not in pages: continue
  adrp_count+=1
  seq=list(C.disasm(data[off:off+0xa0],addr+off))
  if not seq: continue
  values={reg(seq[0],seq[0].operands[0].reg):page}; chain=[ins(seq[0])]
  for i in seq[1:]:
   ops=i.operands
   if i.mnemonic in ('ret','br','blr','bl'): break
   derived=None
   if i.mnemonic in ('add','sub') and len(ops)>=3 and ops[0].type==ops[1].type==ARM64_OP_REG and ops[2].type==ARM64_OP_IMM:
    src=reg(i,ops[1].reg)
    if src in values: derived=(reg(i,ops[0].reg),values[src]+ops[2].imm*(1 if i.mnemonic=='add' else -1))
   elif i.mnemonic=='mov' and len(ops)==2 and ops[0].type==ops[1].type==ARM64_OP_REG:
    src=reg(i,ops[1].reg)
    if src in values: derived=(reg(i,ops[0].reg),values[src])
   if derived and target-0x2a0 <= derived[1] <= target-0x280:
    start=max(0,off-0x20); end=min(len(data),i.address-addr+0x80)
    pointers.append({'adrp':hex(addr+off),'address':hex(i.address),'value':hex(derived[1]),'instruction':ins(i),'context':[ins(x) for x in C.disasm(data[start:end],addr+start)]})
   for op in ops:
    if op.type!=ARM64_OP_MEM: continue
    b=reg(i,op.mem.base)
    if b not in values: continue
    ea=values[b]+op.mem.disp
    if target-0x40<=ea<=target+0x40:
     start=max(0,off-0x30); end=min(len(data),i.address-addr+0x34)
     hits.append({'adrp':hex(addr+off),'address':hex(i.address),'effective_base_plus_displacement':hex(ea),'indexed':bool(op.mem.index),'index':i.reg_name(op.mem.index) if op.mem.index else None,'instruction':ins(i),'address_chain':chain.copy(),'context':[ins(x) for x in C.disasm(data[start:end],addr+start)]})
   try: _,writes=i.regs_access()
   except: writes=[]
   for r in writes: values.pop(reg(i,r),None)
   if derived:
    values[derived[0]]=derived[1]; chain.append(ins(i))
   if not values: break
 return adrp_count,hits,pointers
results=[]
for name,path,expected,offsets,bases,target,mode in MODELS:
 p=ROOT/path; raw=p.read_bytes(); before=hashlib.sha256(raw).hexdigest(); assert before==expected
 translated=raw.translate(base.TRANSLATION); blocks=[]
 for k,(off,addr) in enumerate(zip(offsets,bases)):
  data=base.unpack_fflz(translated,off); assert struct.unpack_from('<Q',data,8)[0]==addr
  if k+1<len(bases): data=data[:bases[k+1]-addr]
  blocks.append((addr,data))
 hits=[]; pointers=[]; count=0; literals=[]
 for a,data in blocks:
  n,h,refs=scan(data,a,target); count+=n; hits.extend(h); pointers.extend(refs)
  for size,fmt in ((4,'<I'),(8,'<Q')):
   needle=struct.pack(fmt,target)
   pos=0
   while True:
    pos=data.find(needle,pos)
    if pos<0: break
    literals.append({'address':hex(a+pos),'width':size,'bytes':needle.hex(),'aligned':(a+pos)%size==0}); pos+=1
 fn,helper,copy,size,field=FUNCS[name]
 def code(address,length):
  return next([ins(i) for i in C.disasm(data[address-a:address-a+length],address)] for a,data in blocks if a<=address and address+length<=a+len(data))
 callers=[]; wrapper_callers=[]; wrapper_literals=[]
 for a,data in blocks:
  for off in range(0,len(data)-4,4):
   w=struct.unpack_from('<I',data,off)[0]
   if w>>26!=0x25: continue
   delta=w&0x3ffffff
   if delta&0x2000000: delta-=0x4000000
   dest=a+off+delta*4
   if dest==fn or dest in WRAPPERS[name]:
    start=max(0,off-0x100); end=min(len(data),off+0x20)
    entry={'address':hex(a+off),'target':hex(dest),'context':[ins(i) for i in C.disasm(data[start:end],a+start)]}
    (callers if dest==fn else wrapper_callers).append(entry)
  for wrapper in WRAPPERS[name]:
   for width,fmt in ((4,'<I'),(8,'<Q')):
    needle=struct.pack(fmt,wrapper); pos=0
    while True:
     pos=data.find(needle,pos)
     if pos<0: break
     wrapper_literals.append({'target':hex(wrapper),'address':hex(a+pos),'width':width,'aligned':(a+pos)%width==0}); pos+=1
 experiments=[]
 for value,synthetic_mode in ((13,0),(0,13)):
  u=Uc(UC_ARCH_ARM64,UC_MODE_ARM); u.mem_map(0x40000,0x5fc0000)
  for a,data in blocks: u.mem_write(a,data)
  u.mem_map(0x70000000,0x20000); source=0x70000000; sp=0x70010000
  fixture=bytearray([0x6b]*size); struct.pack_into('<H',fixture,field,value)
  u.mem_write(source,bytes(fixture)); u.mem_write(target,bytes.fromhex('ccdd')); u.mem_write(mode,struct.pack('<I',synthetic_mode))
  u.reg_write(UC_ARM64_REG_SP,sp); u.reg_write(UC_ARM64_REG_X0,source); u.reg_write(UC_ARM64_REG_X1,0)
  reads=[]; writes=[]
  def hook(uc,access,address,n,val,user):
   if access==16 and address<mode+4 and address+n>mode: reads.append([hex(address),n])
   if access==17 and address<target+2 and address+n>target: writes.append([hex(address),n,hex(val)])
  u.hook_add(UC_HOOK_MEM_READ|UC_HOOK_MEM_WRITE,hook)
  u.emu_start(fn,fn+0x3c,count=100000); assert u.reg_read(UC_ARM64_REG_PC)==fn+0x3c
  copied=struct.unpack('<H',u.mem_read(target,2))[0]; assert copied==value
  u.emu_start(fn+0x3c,fn+0x5c,count=100000); assert u.reg_read(UC_ARM64_REG_PC)==fn+0x5c
  after_helper=struct.unpack('<H',u.mem_read(target,2))[0]
  u.mem_write(target,bytes.fromhex('adde'))
  u.reg_write(UC_ARM64_REG_X0,target-field); u.reg_write(UC_ARM64_REG_X1,0x70001000)
  u.reg_write(UC_ARM64_REG_X2,0); u.reg_write(UC_ARM64_REG_X3,0); u.reg_write(UC_ARM64_REG_X30,0x7001f000)
  u.emu_start(helper-0x70,0x7001f000,count=100000); assert u.reg_read(UC_ARM64_REG_PC)==0x7001f000
  restored=struct.unpack('<H',u.mem_read(target,2))[0]; assert restored==value
  experiments.append({'source':hex(source),'source_offset':hex(field),'synthetic_input':value,'synthetic_saved_mode':synthetic_mode,'post_copy':copied,'post_helper':after_helper,'post_artificial_reverse_helper':restored,'overlapping_target_writes':writes,'saved_mode_reads':reads,'stop_before':hex(fn+0x5c)})
 print('COPY',name,'fn',hex(fn),'callers',[x['address'] for x in callers],'wrapper_callers',[(x['address'],x['target']) for x in wrapper_callers],'wrapper_literals',wrapper_literals,'experiments',experiments,flush=True)
 after=hashlib.sha256(p.read_bytes()).hexdigest(); assert before==after
 results.append({'model':name,'file':path,'sha256_before':before,'sha256_after':after,'target':hex(target),'saved_mode':hex(mode),'blocks':[{'offset':hex(o),'base':hex(a),'size':len(b),'sha256':hashlib.sha256(b).hexdigest()} for o,(a,b) in zip(offsets,blocks)],'adrp_adjacent_pages_count':count,'nearby_accesses':hits,'structure_base_address_constructions':pointers,'exact_address_literals':literals,'producer':hex(fn),'producer_code':code(fn,0x90),'copy_implementation':code(copy,0x100),'post_copy_helper':code(helper,fn-helper),'null_input_helper_candidate':code(helper-0x70,0x70),'direct_callers':callers,'wrappers':list(map(hex,WRAPPERS[name])),'wrapper_direct_callers':wrapper_callers,'wrapper_address_literals':wrapper_literals,'experiments':experiments})
 print(name,'ADRP',count,'hits',len(hits),'pointers',len(pointers),'literals',len(literals),flush=True)
 for h in pointers: print(' pointer',h['address'],h['instruction']['instruction'],h['value'],flush=True)
 for h in hits: print(' ',h['address'],h['instruction']['instruction'],h['effective_base_plus_displacement'],flush=True)
(HERE/'результаты.json').write_text(json.dumps(results,ensure_ascii=False,indent=2)+'\n',encoding='utf-8')
