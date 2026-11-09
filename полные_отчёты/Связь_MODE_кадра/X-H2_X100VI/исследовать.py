from pathlib import Path
import hashlib, importlib.util, json, struct, sys
P=Path(__file__).resolve().parent
FW=P.parents[1]; ROOT=FW.parent
sys.path.insert(0,str(FW/'инструменты'))
spec=importlib.util.spec_from_file_location('base',FW/'анализ_файла.py'); base=importlib.util.module_from_spec(spec);spec.loader.exec_module(base)
from capstone import Cs, CS_ARCH_ARM64, CS_MODE_LITTLE_ENDIAN
from unicorn import Uc, UC_ARCH_ARM64, UC_MODE_ARM, UC_HOOK_CODE
from unicorn.arm64_const import UC_ARM64_REG_X0, UC_ARM64_REG_X1, UC_ARM64_REG_X19, UC_ARM64_REG_X20, UC_ARM64_REG_SP, UC_ARM64_REG_PC
C=Cs(CS_ARCH_ARM64,CS_MODE_LITTLE_ENDIAN);C.detail=True
models=[dict(name='X-H2',path='FIRMWARE/ver 5.30/FWUP0028.DAT',sha='be47168cb075ef726e67cb4bb08175a896047a3b0de2bcb6e65333b22cfcb203',offsets=[0x300274,0x840274],bases=[0x1101000,0x29ae000],state=0x2680414,setter=0x1562e18,wrapper=0x1554a68),dict(name='X100VI',path='Firmware на прочиеFuji/FPUPDATE.DAT',sha='0d48d2ae26ac7ebab9b0e4cac56324807ec1ea8ae30df06b0b9e79066dc0a14a',offsets=[0x9c02bc,0x10e02bc],bases=[0x11c1000,0x2b8f000],state=0x27f7a54,setter=0x162a450,wrapper=0x161ad5c)]
def text(ins):return f'{ins.address:#010x}: {ins.bytes.hex()} {ins.mnemonic} {ins.op_str}'
def main():
 out=[]
 for m in models:
  p=ROOT/m['path'];raw=p.read_bytes();assert hashlib.sha256(raw).hexdigest()==m['sha'];data=raw.translate(base.TRANSLATION)
  blocks=[base.unpack_fflz(data,x) for x in m['offsets']]; regions=[]
  for i,(buf,addr) in enumerate(zip(blocks,m['bases'])):
   assert struct.unpack_from('<Q',buf,8)[0]==addr
   end=min(len(buf),m['bases'][i+1]-addr) if i+1<len(blocks) else len(buf)
   regions.append((addr,buf[:end]))
  def dis(addr,before=0,after=0x40):
   for start,buf in regions:
    off=addr-start-before
    if off>=0 and off+before+after<=len(buf):return [text(i) for i in C.disasm(buf[off:off+before+after],addr-before)]
   return []
  calls=[]; wrappers=[];pages=[]
  for start,buf in regions:
   for off in range(0,len(buf)-3,4):
    w=struct.unpack_from('<I',buf,off)[0]; pc=start+off
    if w>>26==0x25:
     delta=w&0x3ffffff;delta=(delta-(1<<26) if delta&(1<<25) else delta)*4
     if pc+delta==m['setter']:calls.append(pc)
     if pc+delta==m['wrapper']:wrappers.append(pc)
    if w&0x9f000000==0x90000000:
     imm=((w>>29)&3)|(((w>>5)&0x7ffff)<<2);imm=imm-(1<<21) if imm&(1<<20) else imm
     if (pc&~0xfff)+(imm<<12)==m['state']&~0xfff:
      ins=list(C.disasm(buf[off:off+8],pc))
      if len(ins)==2 and ins[1].mnemonic in ('ldr','str') and ins[1].operands[-1].type==3 and ins[1].operands[-1].mem.base==ins[0].operands[0].reg and ins[1].operands[-1].mem.disp==(m['state']&0xfff):pages.append(pc)
  # Execute the original indexed-array -> wrapper -> frame setter path, not the saved-state bridge.
  xh=m['name']=='X-H2'
  source=0x4d1fbc8 if xh else 0x52b6bb8
  frame=0x229e840 if xh else 0x230ff50
  index_default=0x2271500 if xh else 0x22c5768
  entry=0x2fbccb4 if xh else 0x31db22c
  stop=0x2fbccd0 if xh else 0x31db0bc
  experiments=[]
  for handle in (0xffff0000,0xffffffff):
   u=Uc(UC_ARCH_ARM64,UC_MODE_ARM);u.mem_map(m['bases'][0],0x6000000-m['bases'][0])
   for addr,buf in zip(m['bases'],blocks):u.mem_write(addr,buf)
   u.mem_map(0x70000000,0x10000)
   put=lambda addr,val:u.mem_write(addr,struct.pack('<I',val))
   get=lambda addr:struct.unpack('<I',u.mem_read(addr,4))[0]
   put(source,13);put(frame,0xaabbccdd);put(index_default,0)
   u.reg_write(UC_ARM64_REG_X19,handle);u.reg_write(UC_ARM64_REG_X20,0);u.reg_write(UC_ARM64_REG_SP,0x7000f000)
   visited=[]
   def trace(uc,addr,size,user):
    if addr in (m['wrapper'],m['setter']):visited.append(hex(addr))
   u.hook_add(UC_HOOK_CODE,trace)
   u.emu_start(entry,stop,count=10000);assert u.reg_read(UC_ARM64_REG_PC)==stop
   observed=get(frame);assert observed==(13 if handle==0xffff0000 else 0xaabbccdd)
   experiments.append({'entry':hex(entry),'stop':hex(stop),'handle_w19':hex(handle),'index_w20':0,'synthetic_source_address':hex(source),'synthetic_source_value':13,'default_frame_index_address':hex(index_default),'default_frame_index':0,'frame_field':hex(frame),'frame_field_initial':'0xaabbccdd','frame_field_final':hex(observed),'visited':visited})
  saved_consumers=[]
  for ui,equal in ((14,False),(0,False),(14,True)):
   u=Uc(UC_ARCH_ARM64,UC_MODE_ARM);u.mem_map(m['bases'][0],0x6000000-m['bases'][0])
   for addr,buf in zip(m['bases'],blocks):u.mem_write(addr,buf)
   u.mem_map(0x70000000,0x10000)
   put=lambda addr,val:u.mem_write(addr,struct.pack('<I',val))
   get=lambda addr:struct.unpack('<I',u.mem_read(addr,4))[0]
   new,old,flags,entry,stop,reader,reader_stop = ((0x2053f70,0x2051c90,[0x2051408,0x267ebec],0x132d138,0x132d150 if equal else 0x132d5e0,0x2bfacf8,0x2bfad10) if xh else (0x20b7178,0x20b4ec0,[0x20b44c4,0x2897414,0x27f601c],0x1411a3c,0x1411a54 if equal else 0x1411fb4,0x2df7cb0,0x2df7cc8))
   put(new,ui);put(old,ui if equal else (0 if ui else 14));put(m['state'],0)
   for addr in flags:put(addr,0)
   u.reg_write(UC_ARM64_REG_SP,0x7000f000);u.emu_start(entry,stop,count=10000);assert u.reg_read(UC_ARM64_REG_PC)==stop
   saved=get(m['state']);assert saved==(13 if ui==14 and not equal else 0)
   u.emu_start(reader,reader_stop,count=10000);assert u.reg_read(UC_ARM64_REG_PC)==reader_stop
   representation=u.reg_read(UC_ARM64_REG_X0)&0xffffffff
   assert representation==(11 if saved==13 else 1)
   writer=0x2bf8b44 if xh else 0x2df56d4
   u.reg_write(UC_ARM64_REG_X19,0x70001000)
   u.emu_start(reader_stop,writer,count=10000);assert u.reg_read(UC_ARM64_REG_PC)==writer
   writer_arg=u.reg_read(UC_ARM64_REG_X1)&0xffffffff;assert writer_arg==representation
   saved_consumers.append({'new_word':ui,'old_word':ui if equal else (0 if ui else 14),'initial_saved':0,'zeroed_flags':[hex(a) for a in flags],'selection_entry':hex(entry),'selection_stop':hex(stop),'saved':saved,'separate_reader_entry':hex(reader),'reader_conversion_stop':hex(reader_stop),'reader_x0':representation,'synthetic_destination_x19':'0x70001000','writer_entry_stop':hex(writer),'writer_w1':writer_arg,'state_transferred_by_researcher':False})
  result={'model':m['name'],'dat_sha256':m['sha'],'blocks':[{'base':hex(a),'mapped_bytes':len(b),'sha256':hashlib.sha256(b).hexdigest()} for a,b in regions],'state':hex(m['state']),'setter':hex(m['setter']),'wrapper':hex(m['wrapper']),'wrapper_body':dis(m['wrapper'],0,0x74),'direct_bl_setter':[{'address':hex(x),'instructions':dis(x,0x30,0x18)} for x in calls],'direct_bl_wrapper':[{'address':hex(x),'instructions':dis(x,0x30,0x18)} for x in wrappers],'direct_adrp_state_access':[{'address':hex(x),'instructions':dis(x,0,0x30)} for x in pages]}
  result['executed_array_to_frame']=experiments
  result['saved_state_separate_reader']=saved_consumers
  if not xh:result['alternate_array_branch']=dis(0x31db22c,0,0x14)
  assert hashlib.sha256(p.read_bytes()).hexdigest()==m['sha'];out.append(result)
 (P/'результаты.json').write_text(json.dumps(out,ensure_ascii=False,indent=2)+'\n',encoding='utf-8')
 print(json.dumps([{'model':x['model'],'setter_calls':[y['address'] for y in x['direct_bl_setter']],'wrapper_calls':[y['address'] for y in x['direct_bl_wrapper']],'state_access_count':len(x['direct_adrp_state_access'])} for x in out],ensure_ascii=False,indent=2))
if __name__=='__main__':main()
