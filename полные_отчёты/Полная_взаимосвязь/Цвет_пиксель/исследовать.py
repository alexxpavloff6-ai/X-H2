"""Оригинальные инструкции DAT в Unicorn; результаты только в этом каталоге."""
from pathlib import Path
import importlib.util, struct, hashlib, json, sys
sys.dont_write_bytecode=True
HERE=Path(__file__).resolve().parent; ROOT=HERE.parents[2]; FW=ROOT/'Анализ_прошивки'
sys.path.insert(0,str(FW/'инструменты'))
spec=importlib.util.spec_from_file_location('base',FW/'анализ_файла.py'); base=importlib.util.module_from_spec(spec); spec.loader.exec_module(base)
from unicorn import Uc, UC_ARCH_ARM64, UC_MODE_ARM, UC_HOOK_MEM_WRITE
from unicorn import arm64_const as R
from capstone import Cs, CS_ARCH_ARM64, CS_MODE_ARM
C={
'X-H2':('FIRMWARE/ver 5.30/FWUP0028.DAT','be47168cb075ef726e67cb4bb08175a896047a3b0de2bcb6e65333b22cfcb203',0x300274,0x840274,0x60274,0x1e340,0x2d2f4f8,0x1377884,0x18df948),
'X-H2S':('Firmware на прочиеFuji/FWUP0027.DAT','87c566c1ff6343e4c7463a4ef968183f41d1f24cc63d610433d3a387b13f731b',0x300274,0x840274,0x60274,0x1e340,0x3045b98,0x1695464,0x1bfcb20),
'X-T5':('Firmware на прочиеFuji/FWUP0030.DAT','790d6deecf26766188b0e506e40645e6b816addfeba39a52334349405421724e',0x300274,0x820274,0x60274,0x1e340,0x2c6e1c4,0x1374854,0x18dd408),
'X100VI':('Firmware на прочиеFuji/FPUPDATE.DAT','0d48d2ae26ac7ebab9b0e4cac56324807ec1ea8ae30df06b0b9e79066dc0a14a',0x9c02bc,0x10e02bc,0x7f2bc,0x70000,0x2f34cd8,0x145fbdc,0x19dca28)}
STOP=0x70000000; SRC=0x60000000; MM=0xff000000; cs=Cs(CS_ARCH_ARM64,CS_MODE_ARM)
result={}
for name,(path,expected,ao,bo,lo,ln,dispatcher,writer,desc) in C.items():
 source=ROOT/path; raw=source.read_bytes(); before=hashlib.sha256(raw).hexdigest(); assert before==expected
 data=raw.translate(base.TRANSLATION); a=base.unpack_fflz(data,ao); b=base.unpack_fflz(data,bo)
 blocks=[(0x40000,data[lo:lo+ln]),(struct.unpack_from('<Q',a,8)[0],a),(struct.unpack_from('<Q',b,8)[0],b)]
 u=Uc(UC_ARCH_ARM64,UC_MODE_ARM); u.mem_map(0x40000,0x5fc0000)
 for p,block in blocks:u.mem_write(p,block)
 u.mem_map(SRC,0x40000);u.mem_map(STOP,0x10000);u.mem_map(MM,0x1000000)
 descriptors=[]
 for j in range(2):
  reg,offset,count=struct.unpack('<QQH',u.mem_read(desc+j*24,18)); descriptors.append({'entry':hex(desc+j*24),'address':hex(reg),'source_offset':hex(offset),'count':count})
 assert [(d['address'],d['source_offset'],d['count']) for d in descriptors]==[('0xff96c634','0x1ec',1),('0xff96c638','0x1f0',1)]
 hits={}
 for address in (0xff96c634,0xff96c638):
  needle=struct.pack('<Q',address); found=[]
  for start,block in blocks:
   p=block.find(needle)
   while p>=0:
    found.append(hex(start+p));p=block.find(needle,p+1)
  hits[hex(address)]=found
 alt=int(hits['0xff96c634'][0],16)
 alt_descriptors=[]
 for j in range(2):
  reg,offset,count=struct.unpack('<QQH',u.mem_read(alt+j*24,18))
  alt_descriptors.append({'entry':hex(alt+j*24),'address':hex(reg),'source_offset':hex(offset),'count':count})
 writer_ins=list(cs.disasm(bytes(u.mem_read(writer,0x20)),writer))
 generic=int(next(i.op_str[1:] for i in writer_ins if i.mnemonic=='bl'),16)
 reader=generic+0xac
 assert list(cs.disasm(bytes(u.mem_read(reader,4)),reader))[0].mnemonic=='cbz'
 xrefs=[]
 for start,block in blocks[1:]:
  size=len(block)&~3
  for k,(word,) in enumerate(struct.iter_unpack('<I',memoryview(block)[:size])):
   if word & 0x9f000000 != 0x90000000: continue
   pc=start+4*k; imm=((word>>29)&3)|(((word>>5)&0x7ffff)<<2)
   if imm & 0x100000: imm-=0x200000
   page=(pc&~0xfff)+(imm<<12)
   if page not in (alt&~0xfff,desc&~0xfff): continue
   reg=word&31
   for off in range(4,44,4):
    if 4*k+off+4>size: break
    w=struct.unpack_from('<I',block,4*k+off)[0]
    if w & 0xffc00000 != 0x91000000 or (w>>5)&31 != reg: continue
    addr=page+((w>>10)&0xfff)
    if addr in (alt,desc):
     xrefs.append({'descriptor':hex(addr),'adrp':hex(pc),'add':hex(pc+off),'adrp_register':reg,'note':'candidate nearby ADRP/ADD; register clobbers not analysed'})
 events=[]
 def hook(uc,access,address,size,value,user):
  events.append({'pc':hex(uc.reg_read(R.UC_ARM64_REG_PC)),'address':hex(address),'size':size,'value':hex(value)})
 u.hook_add(UC_HOOK_MEM_WRITE,hook,begin=MM,end=0xffffffff)
 def run(entry,x0,x1,x2=0):
  for k in range(31):u.reg_write(getattr(R,'UC_ARM64_REG_X'+str(k)),0)
  u.reg_write(R.UC_ARM64_REG_SP,STOP+0xf000);u.reg_write(R.UC_ARM64_REG_X30,STOP);u.reg_write(R.UC_ARM64_REG_X0,x0);u.reg_write(R.UC_ARM64_REG_X1,x1);u.reg_write(R.UC_ARM64_REG_X2,x2)
  events.clear(); error=None
  try:
   u.emu_start(entry,STOP,count=200000,timeout=2000000)
   if u.reg_read(R.UC_ARM64_REG_PC)!=STOP:error='instruction limit or timeout'
  except Exception as e:error=str(e)
  return {'end_pc':hex(u.reg_read(R.UC_ARM64_REG_PC)),'error':error,'writes':list(events)}
 cases=[]
 for label,values in [('A',(0x1ff60375,0x1ff4035b)),('B',(0x12345678,0x9abcdef0))]:
  u.mem_write(SRC,bytes(0x4000));u.mem_write(SRC+0x1ec,struct.pack('<II',*values))
  for mask in (0,0x40,0x80,0x81,0x100,0x100000):
   out=run(dispatcher,mask,SRC); cases.append({'entry':'dispatcher','source':label,'source_words':[hex(x) for x in values],'mask':hex(mask),**out})
  out=run(writer,SRC,0);cases.append({'entry':'direct_writer','source':label,'source_words':[hex(x) for x in values],**out})
 cases.append({'entry':'dispatcher_null','mask':'0x80',**run(dispatcher,0x80,0)})
 u.mem_write(SRC,bytes(0x4000))
 for d,v in zip(alt_descriptors,(0x11223344,0xaabbccdd)):
  u.mem_write(SRC+int(d['source_offset'],16),struct.pack('<I',v))
 cases.append({'entry':'generic_with_alternative_descriptor','descriptor':hex(alt),**run(generic,SRC,alt,2)})
 u.mem_write(0xff96c634,struct.pack('<II',0x55667788,0xdeadbeef))
 u.mem_write(SRC+0x1ec,bytes(8))
 observed=run(reader,SRC,desc,2)
 cases.append({'entry':'generic_readback','descriptor':hex(desc),'seed_virtual':[hex(0x55667788),hex(0xdeadbeef)],'read_words':[hex(v) for v in struct.unpack('<II',u.mem_read(SRC+0x1ec,8))],**observed})
 asm=[]
 for address,size in [(dispatcher,0x194),(writer,0x20),(generic,0x158)]:
  asm.extend({'address':hex(i.address),'bytes':i.bytes.hex(),'text':i.mnemonic+' '+i.op_str} for i in cs.disasm(bytes(u.mem_read(address,size)),address))
 after=hashlib.sha256(source.read_bytes()).hexdigest(); assert before==after
 result[name]={'source':path,'sha256_before':before,'sha256_after':after,'decoded_blocks':[{'dat_offset':hex(off),'mapped_base':hex(p),'size':len(block),'sha256':hashlib.sha256(block).hexdigest()} for off,(p,block) in zip((lo,ao,bo),blocks)],'dispatcher':hex(dispatcher),'writer':hex(writer),'generic_writer':hex(generic),'generic_reader':hex(reader),'descriptors':descriptors,'alternative_descriptors':alt_descriptors,'absolute_address_literal_hits':hits,'descriptor_candidate_adrp_add':xrefs,'instruction_listing':asm,'cases':cases}
 print(name, [(x['entry'],x.get('mask'),x['error'],[(w['address'],w['value']) for w in x['writes'] if w['address'] in ('0xff96c634','0xff96c638')]) for x in cases],flush=True)
(HERE/'Результаты.json').write_text(json.dumps(result,ensure_ascii=False,indent=2)+'\n',encoding='utf-8')
