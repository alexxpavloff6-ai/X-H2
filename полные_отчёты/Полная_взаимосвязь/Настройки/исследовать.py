from pathlib import Path
import sys, hashlib, importlib.util, struct, json
sys.dont_write_bytecode=True
P=Path(__file__).resolve().parent
AN=P.parents[1]; ROOT=AN.parent
sys.path.insert(0,str(AN/'инструменты'))
spec=importlib.util.spec_from_file_location('base',AN/'анализ_файла.py'); base=importlib.util.module_from_spec(spec);spec.loader.exec_module(base)
from capstone import Cs, CS_ARCH_ARM64, CS_MODE_LITTLE_ENDIAN
from capstone.arm64 import ARM64_OP_REG, ARM64_OP_IMM, ARM64_OP_MEM
from unicorn import Uc, UC_ARCH_ARM64, UC_MODE_ARM
from unicorn.arm64_const import UC_ARM64_REG_SP, UC_ARM64_REG_PC
writers={
 'X-H2':[(0x2fb2a30,0x2fb2a38,0x2fb2a4c,2),(0x2fb2f48,0x2fb2f68,0x2fb2f7c,1)],
 'X-H2S':[(0x32c802c,0x32c8034,0x32c8048,2),(0x32c8544,0x32c8564,0x32c8578,1)],
 'X-T5':[(0x2eee7ec,0x2eee7f4,0x2eee808,2),(0x2eeed04,0x2eeed20,0x2eeed34,1)],
 'X100VI':[(0x31d054c,0x31d0554,0x31d0568,2),(0x31d0a80,0x31d0a9c,0x31d0ab0,1)]}
zero_sites={'X-H2':0x2fb42b8,'X-H2S':0x32c98b4,'X-T5':0x2eefd08,'X100VI':0x31d1a84}
C=Cs(CS_ARCH_ARM64,CS_MODE_LITTLE_ENDIAN);C.detail=True
models=[
('X-H2','FIRMWARE/ver 5.30/FWUP0028.DAT','be47168cb075ef726e67cb4bb08175a896047a3b0de2bcb6e65333b22cfcb203',[0x300274,0x840274],[0x1101000,0x29ae000],0x4d1fbc8),
('X-H2S','Firmware на прочиеFuji/FWUP0027.DAT','87c566c1ff6343e4c7463a4ef968183f41d1f24cc63d610433d3a387b13f731b',[0x300274,0x840274],[0x1421000,0x2cca000],0x4c935c8),
('X-T5','Firmware на прочиеFuji/FWUP0030.DAT','790d6deecf26766188b0e506e40645e6b816addfeba39a52334349405421724e',[0x300274,0x820274],[0x1101000,0x28eb000],0x4ba6948),
('X100VI','Firmware на прочиеFuji/FPUPDATE.DAT','0d48d2ae26ac7ebab9b0e4cac56324807ec1ea8ae30df06b0b9e79066dc0a14a',[0x9c02bc,0x10e02bc],[0x11c1000,0x2b8f000],0x52b6bb8)]
def fmt(i): return {'address':hex(i.address),'bytes':i.bytes.hex(),'instruction':i.mnemonic+' '+i.op_str}
result=[]
for name,path,sha,offsets,bases,target in models:
 p=ROOT/path; raw=p.read_bytes(); before=hashlib.sha256(raw).hexdigest(); assert before==sha
 data=raw.translate(base.TRANSLATION); blocks=[]
 for n,(off,addr) in enumerate(zip(offsets,bases)):
  b=base.unpack_fflz(data,off); assert struct.unpack_from('<Q',b,8)[0]==addr
  if n+1<len(bases): b=b[:bases[n+1]-addr]
  blocks.append((addr,b))
 z=zero_sites[name]; candidates=[]
 for a,b in blocks:
  if a<=z-0x3000 and z<a+len(b):
   candidates=[i.address for i in C.disasm(b[z-a-0x3000:z-a],z-0x3000) if i.mnemonic=='stp' and i.op_str.startswith('x29, x30, [sp, #-')]
 zero_candidate=candidates[-1] if candidates else 0
 refs=[]; calls={hex(x[0]):[] for x in writers[name]};calls[hex(zero_candidate)]=[]
 for addr,b in blocks:
  for o in range(0,len(b)-3,4):
   w=struct.unpack_from('<I',b,o)[0]
   if w>>26==0x25:
    delta=w&0x3ffffff; delta=(delta-(1<<26) if delta&(1<<25) else delta)*4
    dest=hex(addr+o+delta)
    if dest in calls: calls[dest].append(hex(addr+o))
   if w&0x9f000000!=0x90000000: continue
   imm=((w>>29)&3)|(((w>>5)&0x7ffff)<<2); imm=imm-(1<<21) if imm&(1<<20) else imm
   page=((addr+o)&~0xfff)+(imm<<12)
   if not target-0x3000<=page<=target+0x1000: continue
   seq=list(C.disasm(b[o:o+100],addr+o)); regs={seq[0].operands[0].reg:page}; matches=[]
   for ins in seq[1:]:
    op=ins.operands
    if ins.mnemonic in ('bl','blr','b','br','ret'): break
    if ins.mnemonic=='add' and len(op)>=3 and op[0].type==op[1].type==ARM64_OP_REG and op[2].type==ARM64_OP_IMM:
     if op[1].reg in regs: regs[op[0].reg]=regs[op[1].reg]+op[2].imm
     else: regs.pop(op[0].reg,None)
    elif ins.mnemonic=='add' and len(op)>=3 and op[0].type==op[1].type==op[2].type==ARM64_OP_REG:
     if op[1].reg in regs: regs[op[0].reg]=regs[op[1].reg]
     else: regs.pop(op[0].reg,None)
    elif ins.mnemonic.startswith(('ldr','str')):
     for x in op:
      if x.type==ARM64_OP_MEM and x.mem.base in regs:
       value=regs[x.mem.base]+x.mem.disp
       if target-0x10<=value<target+0x400: matches.append({'instruction':fmt(ins),'base_plus_displacement':hex(value),'indexed':bool(x.mem.index)})
     if ins.mnemonic.startswith('ldr') and op and op[0].type==ARM64_OP_REG: regs.pop(op[0].reg,None)
    elif op and op[0].type==ARM64_OP_REG:
     if ins.mnemonic not in ('cmp','tst','cbz','cbnz','tbz','tbnz'): regs.pop(op[0].reg,None)
   if matches: refs.append({'adrp':hex(addr+o),'matches':matches,'context':[fmt(i) for i in C.disasm(b[max(0,o-48):o+124],addr+max(0,o-48))]})
 experiments=[]
 for function,start,stop,value in writers[name]:
  u=Uc(UC_ARCH_ARM64,UC_MODE_ARM); u.mem_map(0x40000,0x5fc0000)
  for a,b in blocks: u.mem_write(a,b)
  u.mem_map(0x70000000,0x10000);u.reg_write(UC_ARM64_REG_SP,0x7000f000)
  u.mem_write(target+16,struct.pack('<II',0xaabbccdd,0x11223344))
  u.emu_start(start,stop,count=100); assert u.reg_read(UC_ARM64_REG_PC)==stop
  actual=struct.unpack('<II',u.mem_read(target+16,8)); assert actual==(value,0)
  experiments.append({'function':hex(function),'start':hex(start),'stop_before_call':hex(stop),'initial_words':['0xaabbccdd','0x11223344'],'result_words':[hex(x) for x in actual],'addresses':[hex(target+16),hex(target+20)],'function_direct_bl':calls[hex(function)]})
 z=zero_sites[name]; zero_context=[]
 for a,b in blocks:
  if a<=z-0x80 and z+0x100<=a+len(b): zero_context=[fmt(i) for i in C.disasm(b[z-a-0x80:z-a+0x100],z-0x80)]
 after=hashlib.sha256(p.read_bytes()).hexdigest(); assert after==before
 result.append({'model':name,'file':path,'sha256_before':before,'sha256_after':after,'target':hex(target),'blocks':[{'dat_offset':hex(off),'base':hex(a),'bytes':len(b),'sha256':hashlib.sha256(b).hexdigest()} for off,(a,b) in zip(offsets,blocks)],'references':refs,'writer_fragments_executed':experiments,'zero_site_context':zero_context,'zero_nearest_candidate_prologue':hex(zero_candidate),'zero_candidate_direct_bl':calls[hex(zero_candidate)]})
 print(name,'refs',len(refs),flush=True)
(P/'результаты.json').write_text(json.dumps(result,ensure_ascii=False,indent=2)+'\n',encoding='utf-8')
