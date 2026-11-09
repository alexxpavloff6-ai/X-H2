"""Ограниченный поиск в декодированных блоках DAT и эксперимент ARM64 в Unicorn."""
from pathlib import Path
import hashlib, importlib.util, json, re, struct, sys
sys.dont_write_bytecode=True
HERE=Path(__file__).resolve().parent
ROOT=HERE.parents[3]; FW=ROOT/'Анализ_прошивки'
sys.path.insert(0,str(FW/'инструменты'))
spec=importlib.util.spec_from_file_location('decoder',FW/'анализ_файла.py'); decoder=importlib.util.module_from_spec(spec);spec.loader.exec_module(decoder)
from capstone import Cs, CS_ARCH_ARM64, CS_MODE_ARM
from unicorn import Uc, UC_ARCH_ARM64, UC_MODE_ARM, UC_HOOK_MEM_WRITE
from unicorn import arm64_const as R
C={
'X-H2':('FIRMWARE/ver 5.30/FWUP0028.DAT','be47168cb075ef726e67cb4bb08175a896047a3b0de2bcb6e65333b22cfcb203',0x300274,0x840274,0x60274,0x1e340,0x1377884,0x18df948,0x18df078,0x1373e84,0x1373f30),
'X-H2S':('Firmware на прочиеFuji/FWUP0027.DAT','87c566c1ff6343e4c7463a4ef968183f41d1f24cc63d610433d3a387b13f731b',0x300274,0x840274,0x60274,0x1e340,0x1695464,0x1bfcb20,0x1bfc250,0x1691a64,0x1691b10),
'X-T5':('Firmware на прочиеFuji/FWUP0030.DAT','790d6deecf26766188b0e506e40645e6b816addfeba39a52334349405421724e',0x300274,0x820274,0x60274,0x1e340,0x1374854,0x18dd408,0x18dcb38,0x1370e54,0x1370f00),
'X100VI':('Firmware на прочиеFuji/FPUPDATE.DAT','0d48d2ae26ac7ebab9b0e4cac56324807ec1ea8ae30df06b0b9e79066dc0a14a',0x9c02bc,0x10e02bc,0x7f2bc,0x70000,0x145fbdc,0x19dca28,0x19dc158,0x145c1dc,0x145c288)}
cs=Cs(CS_ARCH_ARM64,CS_MODE_ARM)
result={'method':{'blocks':'low decoded + two FFLZ, separately; second FFLZ wins on VM overlap','strings':'ASCII sequences >=4, case-insensitive regex csc|chroma|saturat|color.?matrix|colour.?matrix|yuv|ycbcr; matches are not proven xrefs','direct_calls':'aligned A64 BL immediate over all bytes of three blocks; candidates may be data; no indirect calls','pointer_literals':'exact little-endian u64, byte-aligned, in three raw decoded blocks','descriptors':'24-byte records -8..+9 relative to each pair, without asserting table boundary'},'models':{}}
for name,(path,expected,ao,bo,lo,ln,writer,desc,alt,generic,reader) in C.items():
 source=ROOT/path; raw=source.read_bytes();before=hashlib.sha256(raw).hexdigest();assert before==expected
 data=raw.translate(decoder.TRANSLATION); a=decoder.unpack_fflz(data,ao);b=decoder.unpack_fflz(data,bo)
 blocks=[(0x40000,data[lo:lo+ln]),(struct.unpack_from('<Q',a,8)[0],a),(struct.unpack_from('<Q',b,8)[0],b)]
 u=Uc(UC_ARCH_ARM64,UC_MODE_ARM);u.mem_map(0x40000,0x5fc0000)
 for p,blk in blocks:u.mem_write(p,blk)
 model={'source':path,'sha256_before':before,'blocks':[{'base':hex(p),'length':len(blk),'sha256':hashlib.sha256(blk).hexdigest()} for p,blk in blocks],'writer':hex(writer),'generic_writer':hex(generic),'generic_reader':hex(reader)}
 model['descriptor_neighborhoods']={}
 for label,addr in [('primary',desc),('alternative',alt)]:
  rec=[]
  for n in range(-8,10):
   at=addr+n*24;v=bytes(u.mem_read(at,24));x,y,z=struct.unpack_from('<QQH',v)
   rec.append({'relative':n,'entry':hex(at),'bytes':v.hex(),'qword0':hex(x),'qword1':hex(y),'u16_16':z})
  model['descriptor_neighborhoods'][label]=rec
 targets=[writer,generic,reader,desc,alt];hits={hex(t):[] for t in targets};calls={hex(t):[] for t in targets[:3]};strings=[]
 pattern=re.compile(rb'csc|chroma|saturat|colou?r.?matrix|yuv|ycbcr',re.I)
 for start,blk in blocks:
  for t in targets:
   needle=struct.pack('<Q',t);p=blk.find(needle)
   while p>=0:hits[hex(t)].append(hex(start+p));p=blk.find(needle,p+1)
  for m in re.finditer(rb'[\x20-\x7e]{4,}',blk):
   s=m.group()
   if pattern.search(s):strings.append({'address':hex(start+m.start()),'text':s.decode('ascii')})
  size=len(blk)&~3
  for k,(w,) in enumerate(struct.iter_unpack('<I',memoryview(blk)[:size])):
   if w&0xfc000000 != 0x94000000:continue
   imm=w&0x3ffffff
   if imm&0x2000000:imm-=0x4000000
   pc=start+k*4;dest=pc+(imm<<2)
   if dest in targets[:3]:calls[hex(dest)].append(hex(pc))
 model['exact_u64_pointer_hits']=hits;model['direct_bl_candidates']=calls;model['diagnostic_string_candidates']=strings
 model['callsite_windows']={key:[{'call':addr,'listing':[{'address':hex(i.address),'bytes':i.bytes.hex(),'instruction':i.mnemonic+' '+i.op_str} for i in cs.disasm(bytes(u.mem_read(int(addr,16)-0x20,0x28)),int(addr,16)-0x20)]} for addr in addresses] for key,addresses in calls.items()}
 model['bulk_covering_alternative']=[]
 for target,windows in model['callsite_windows'].items():
  for window in windows:
   ins=window['listing']; texts=[x['instruction'] for x in ins]
   for j in range(len(ins)-3):
    a=re.fullmatch(r'mov w2, #(0x[0-9a-f]+|[0-9]+)',texts[j])
    b=re.fullmatch(r'adrp x1, #(0x[0-9a-f]+)',texts[j+1])
    c=re.fullmatch(r'add x1, x1, #(0x[0-9a-f]+|[0-9]+)',texts[j+2])
    if a and b and c:
     count=int(a.group(1),0);base_addr=int(b.group(1),0)+int(c.group(1),0)
     if base_addr<=alt and alt+24<base_addr+24*count and (alt-base_addr)%24==0:
      model['bulk_covering_alternative'].append({'generic_target':target,'call':window['call'],'table_base':hex(base_addr),'count':count,'pair_index':(alt-base_addr)//24,'window':ins})
 if model['bulk_covering_alternative']:
  table=int(model['bulk_covering_alternative'][0]['table_base'],16)
  count=model['bulk_covering_alternative'][0]['count'];records=[]
  for j in range(count):
   at=table+24*j;raw_record=bytes(u.mem_read(at,24));reg,offset,num=struct.unpack_from('<QQH',raw_record)
   records.append({'index':j,'entry':hex(at),'address':hex(reg),'source_offset':hex(offset),'count':num,'bytes':raw_record.hex()})
  model['bulk_table_records']=records
 model['writer_preceding_asm']=[{'address':hex(i.address),'bytes':i.bytes.hex(),'instruction':i.mnemonic+' '+i.op_str} for i in cs.disasm(bytes(u.mem_read(writer-0xc0,0xe0)),writer-0xc0)]
 if name=='X-H2':
  # In the analogous X100VI function, the packer starts writer-0xb4.
  # Its own instruction listing and the controls below are preserved, not inferred from its name.
  packer=writer-0xb4;src=0x60000000;dst=src+0x10000;stop=0x70000000
  u.mem_map(src,0x40000);u.mem_map(stop,0x10000);u.mem_map(0xff000000,0x1000000)
  writes=[]
  def on_write(uc,access,address,size,value,user):
   writes.append({'pc':hex(uc.reg_read(R.UC_ARM64_REG_PC)),'address':hex(address),'size':size,'value':hex(value)})
  u.hook_add(UC_HOOK_MEM_WRITE,on_write,begin=0xff000000,end=0xffffffff)
  def execute(entry,args):
   for k in range(31):u.reg_write(getattr(R,'UC_ARM64_REG_X'+str(k)),0)
   u.reg_write(R.UC_ARM64_REG_SP,stop+0xf000);u.reg_write(R.UC_ARM64_REG_X30,stop)
   for k,v in enumerate(args):u.reg_write(getattr(R,'UC_ARM64_REG_X'+str(k)),v)
   u.emu_start(entry,stop,count=200000,timeout=2000000)
   if u.reg_read(R.UC_ARM64_REG_PC)!=stop:raise RuntimeError('instruction limit or timeout')
  cases=[]
  for values,upper in [([885,-10,859,-12],[0,0,0,0]),([-4097,-4096,4095,4096],[0xe000,0xa000,0x6000,0x2000]),([-32768,-1,0,32767],[0x2000,0x4000,0x8000,0xe000])]:
   u.mem_write(src,bytes(0x1000));u.mem_write(dst,bytes(0x1000))
   u.mem_write(src+0x1da,struct.pack('<4h',*values));u.mem_write(dst+0x1ec,struct.pack('<4H',*upper))
   writes.clear();execute(packer,[src,dst]);fields=list(struct.unpack('<4H',u.mem_read(dst+0x1ec,8)))
   execute(writer,[dst]);cases.append({'input_signed16':values,'initial_upper':upper,'packed_u16':fields,'virtual_mmio_writes':list(writes),'end_pc':hex(u.reg_read(R.UC_ARM64_REG_PC))})
  model['xh2_packer_experiment']={'entry':hex(packer),'input_offset':'0x1da','output_offset':'0x1ec','cases':cases,'instruction_listing':[{'address':hex(i.address),'bytes':i.bytes.hex(),'instruction':i.mnemonic+' '+i.op_str} for i in cs.disasm(bytes(u.mem_read(packer,0xb4)),packer)],'note':'separate researcher calls; MMIO is plain Unicorn RAM'}
  model['xh2_signed13_helper_listing']=[{'address':hex(i.address),'bytes':i.bytes.hex(),'instruction':i.mnemonic+' '+i.op_str} for i in cs.disasm(bytes(u.mem_read(0x1373e04,0x80)),0x1373e04)]
  bulk=[]
  for target in (generic,reader):
   candidates=[x for x in model['bulk_covering_alternative'] if int(x['generic_target'],16)==target]
   for item in candidates:
    call=int(item['call'],16);entry=call-0x14
    assert bytes(u.mem_read(entry,4))==bytes.fromhex('fd7bbfa9')
    u.mem_write(src,bytes(0x4000));writes.clear()
    if target==generic:u.mem_write(src+0x1ec,struct.pack('<II',0x12345678,0x9abcdef0))
    else:u.mem_write(0xff96c634,struct.pack('<II',0x55667788,0xdeadbeef))
    execute(entry,[src])
    bulk.append({'kind':'writer' if target==generic else 'reader','wrapper':hex(entry),'call':hex(call),'end_pc':hex(u.reg_read(R.UC_ARM64_REG_PC)),'pair_source_or_result':[hex(x) for x in struct.unpack('<II',u.mem_read(src+0x1ec,8))],'pair_virtual_words':[hex(x) for x in struct.unpack('<II',u.mem_read(0xff96c634,8))],'all_virtual_writes':list(writes)})
  model['xh2_bulk_wrapper_experiment']=bulk
 after=hashlib.sha256(source.read_bytes()).hexdigest();assert before==after;model['sha256_after']=after
 result['models'][name]=model
 print(name,'strings',len(strings),'calls', {k:len(v) for k,v in calls.items()},flush=True)
(HERE/'результаты.json').write_text(json.dumps(result,ensure_ascii=False,indent=2)+'\n',encoding='utf-8')
