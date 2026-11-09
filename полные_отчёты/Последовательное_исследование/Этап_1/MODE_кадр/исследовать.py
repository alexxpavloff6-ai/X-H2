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
from unicorn import Uc, UC_ARCH_ARM64, UC_MODE_ARM, UC_HOOK_MEM_READ
from unicorn.arm64_const import UC_ARM64_REG_X0, UC_ARM64_REG_X21, UC_ARM64_REG_X30, UC_ARM64_REG_SP, UC_ARM64_REG_PC
C = Cs(CS_ARCH_ARM64, CS_MODE_LITTLE_ENDIAN)
MODELS = [
 ('X-H2','FIRMWARE/ver 5.30/FWUP0028.DAT','be47168cb075ef726e67cb4bb08175a896047a3b0de2bcb6e65333b22cfcb203',[0x300274,0x840274],[0x1101000,0x29ae000],0x4d1fbc8,0x2680414),
 ('X-H2S','Firmware на прочиеFuji/FWUP0027.DAT','87c566c1ff6343e4c7463a4ef968183f41d1f24cc63d610433d3a387b13f731b',[0x300274,0x840274],[0x1421000,0x2cca000],0x4c935c8,0x299c40c),
 ('X-T5','Firmware на прочиеFuji/FWUP0030.DAT','790d6deecf26766188b0e506e40645e6b816addfeba39a52334349405421724e',[0x300274,0x820274],[0x1101000,0x28eb000],0x4ba6948,0x25bcccc),
 ('X100VI','Firmware на прочиеFuji/FPUPDATE.DAT','0d48d2ae26ac7ebab9b0e4cac56324807ec1ea8ae30df06b0b9e79066dc0a14a',[0x9c02bc,0x10e02bc],[0x11c1000,0x2b8f000],0x52b6bb8,0x27f7a54)]
def inst(data, addr):
 return [dict(address=hex(i.address),bytes=i.bytes.hex(),instruction=i.mnemonic+' '+i.op_str) for i in C.disasm(data,addr)]
results=[]
for name,path,expected,offsets,bases,B,mode in MODELS:
 p=ROOT/path; raw=p.read_bytes(); before=hashlib.sha256(raw).hexdigest(); assert before==expected
 translated=raw.translate(base.TRANSLATION); blocks=[]
 for k,(off,addr) in enumerate(zip(offsets,bases)):
  data=base.unpack_fflz(translated,off); assert struct.unpack_from('<Q',data,8)[0]==addr
  if k+1<len(bases): data=data[:bases[k+1]-addr]
  blocks.append((addr,data))
 candidates=[]
 for addr,data in blocks:
  for off in range(0,len(data)-20,4):
   if data[off:off+4] != bytes.fromhex('a11a4079'): continue
   seq=inst(data[off:off+20],addr+off)
   if len(seq)<4 or seq[1]['instruction'].split()[0]!='adrp': continue
   if not any(x['instruction'].startswith('strh w1, [x0, #') for x in seq[2:5]): continue
   candidates.append({'address':hex(addr+off),'instructions':seq,'context':inst(data[max(0,off-0x600):off+0x60],addr+max(0,off-0x600))})
 function={'X-H2':0x2fbfcc4,'X-H2S':0x32d5530,'X-T5':0x2efc194,'X100VI':0x31de22c}[name]
 helper={'X-H2':0x2fb3988,'X-H2S':0x32c8f84,'X-T5':0x2eef728,'X100VI':0x31d14a8}[name]
 helper_code=next(inst(b[helper-a:helper-a+0x48],helper) for a,b in blocks if a<=helper and helper+0x48<=a+len(b))
 source_base={'X-H2':0x38e1e60,'X-H2S':0x3b59e60,'X-T5':0x3809660,'X100VI':0x4133238}[name]
 copy_fn={'X-H2':0x153ce8c,'X-H2S':0x185c86c,'X-T5':0x1532c58,'X100VI':0x1606690}[name]
 copy_code=next(inst(b[copy_fn-a:copy_fn-a+0x100],copy_fn) for a,b in blocks if a<=copy_fn and copy_fn+0x100<=a+len(b))
 callers=[]
 for addr,data in blocks:
  for off in range(0,len(data)-4,4):
   word=struct.unpack_from('<I',data,off)[0]
   if word>>26 != 0x25: continue
   d=word & 0x3ffffff
   if d & 0x2000000: d-=0x4000000
   target=addr+off+4*d
   if target in (function,helper,helper+0x20):
    callers.append({'address':hex(addr+off),'target':hex(target),'context':inst(data[max(0,off-0x100):off+0x20],addr+max(0,off-0x100))})
 experiments=[]
 for candidate in candidates:
  start=int(candidate['address'],16)
  store=next(int(x['address'],16) for x in candidate['instructions'] if x['instruction'].startswith('strh w1, [x0, #'))
  for source,old in [(0x1234000d,0xaabbccdd),(0x98760000,0x11223344)]:
   u=Uc(UC_ARCH_ARM64,UC_MODE_ARM); u.mem_map(0x40000,0x5fc0000)
   for a,b in blocks: u.mem_write(a,b)
   u.mem_map(0x70000000,0x1000); u.mem_write(0x7000000c,struct.pack('<I',source))
   u.mem_write(B+12,struct.pack('<I',old)); u.reg_write(UC_ARM64_REG_X21,0x70000000)
   reads=[]
   def hook(uc,access,address,size,value,user):
    if address<mode+4 and address+size>mode: reads.append([hex(address),size])
   u.hook_add(UC_HOOK_MEM_READ,hook)
   u.emu_start(start,store+4,count=10); assert u.reg_read(UC_ARM64_REG_PC)==store+4
   result=struct.unpack('<I',u.mem_read(B+12,4))[0]
   assert result==(old&0xffff0000)|(source&0xffff)
   experiments.append(dict(start=hex(start),end_before=hex(store+4),synthetic_x21='0x70000000',source_word=hex(source),old_destination_word=hex(old),new_destination_word=hex(result),saved_mode_read_overlaps=reads))
 copy_experiments=[]
 for value in (13,0):
  u=Uc(UC_ARCH_ARM64,UC_MODE_ARM); u.mem_map(0x40000,0x5fc0000)
  for a,b in blocks: u.mem_write(a,b)
  u.mem_map(0x70000000,0x20000); sp=0x70010000; dest=0x70001000
  source_data=bytearray([0x6b]*0x1bc); struct.pack_into('<H',source_data,0x1b8,value)
  u.mem_write(source_base,bytes(source_data)); u.mem_write(dest,bytes([0xa5]*0x1bc))
  u.reg_write(UC_ARM64_REG_SP,sp); u.reg_write(UC_ARM64_REG_X0,dest); u.reg_write(UC_ARM64_REG_X30,0x70000000)
  u.emu_start(helper,0x70000000,count=100000)
  assert u.reg_read(UC_ARM64_REG_PC)==0x70000000
  output=bytes(u.mem_read(dest,0x1bc)); assert output==source_data
  copy_experiments.append({'source_base':hex(source_base),'source_offset':'0x1b8','synthetic_halfword':value,'destination':hex(dest),'size':'0x1bc','copied_halfword':struct.unpack_from('<H',output,0x1b8)[0],'whole_block_equal':output==source_data})
 transfer={'X-H2':0x2fc0304,'X-H2S':0x32d5b70,'X-T5':0x2efc7ac,'X100VI':0x31de88c}[name]
 cycles=[]
 for synthetic_mode in (0,13):
  u=Uc(UC_ARCH_ARM64,UC_MODE_ARM); u.mem_map(0x40000,0x5fc0000)
  for a,b in blocks: u.mem_write(a,b)
  u.mem_map(0x70000000,0x20000); sp=0x70010000
  u.reg_write(UC_ARM64_REG_SP,sp); u.mem_write(mode,struct.pack('<I',synthetic_mode))
  u.mem_write(B-0x1ac,bytes([0x27]*0x1bc)); u.mem_write(B+12,struct.pack('<I',0xabcd0035))
  reads=[]
  def hook_cycle(uc,access,address,size,value,user):
   if address<mode+4 and address+size>mode: reads.append([hex(address),size])
  u.hook_add(UC_HOOK_MEM_READ,hook_cycle)
  for start,arg in ((helper+0x20,B-0x1ac),(helper,sp+0x30)):
   u.reg_write(UC_ARM64_REG_X0,arg); u.reg_write(UC_ARM64_REG_X30,0x70000000)
   u.emu_start(start,0x70000000,count=100000); assert u.reg_read(UC_ARM64_REG_PC)==0x70000000
  u.emu_start(transfer,transfer+8,count=10); assert u.reg_read(UC_ARM64_REG_PC)==transfer+8
  u.reg_write(UC_ARM64_REG_X21,sp+0x1f0)
  start=int(candidates[2]['address'],16)
  store=next(int(x['address'],16) for x in candidates[2]['instructions'] if x['instruction'].startswith('strh w1, [x0, #'))
  u.emu_start(start,store+4,count=10); assert u.reg_read(UC_ARM64_REG_PC)==store+4
  cached=struct.unpack('<H',u.mem_read(source_base+0x1b8,2))[0]
  copied=struct.unpack('<H',u.mem_read(sp+0x1fc,2))[0]
  final=struct.unpack('<I',u.mem_read(B+12,4))[0]
  assert (cached,copied,final)==(0x35,0x35,0xabcd0035) and not reads
  cycles.append({'synthetic_saved_mode':synthetic_mode,'initial_destination_word':'0xabcd0035','reverse_helper':hex(helper+0x20),'reverse_source':hex(B-0x1ac),'cached_halfword':hex(cached),'forward_helper':hex(helper),'artificial_stack':hex(sp),'transfer':hex(transfer),'artificial_x21':hex(sp+0x1f0),'writer_fragment':hex(start),'copied_halfword':hex(copied),'final_destination_word':hex(final),'saved_mode_read_overlaps':reads})
 after=hashlib.sha256(p.read_bytes()).hexdigest(); assert before==after
 results.append(dict(model=name,file=path,sha256_before=before,sha256_after=after,B=hex(B),saved_mode=hex(mode),blocks=[dict(offset=hex(o),base=hex(a),size=len(b),sha256=hashlib.sha256(b).hexdigest()) for o,(a,b) in zip(offsets,blocks)],function=hex(function),helper=helper_code,copy_implementation=copy_code,direct_callers=callers,candidates=candidates,experiments=experiments,copy_experiments=copy_experiments,synthetic_cycles=cycles))
 print(name,[(x['address'],[i['instruction'] for i in x['instructions']]) for x in candidates],flush=True)
(HERE/'результаты.json').write_text(json.dumps(results,ensure_ascii=False,indent=2)+'\n',encoding='utf-8')
