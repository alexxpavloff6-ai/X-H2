from pathlib import Path
import hashlib, importlib.util, json, struct, sys

HERE = Path(__file__).resolve().parent
ROOT = HERE.parents[2]
A = ROOT / 'Анализ_прошивки'
sys.path.insert(0, str(A / 'инструменты'))
from unicorn import Uc, UC_ARCH_ARM64, UC_MODE_ARM, UC_HOOK_CODE
from unicorn.arm64_const import *
spec = importlib.util.spec_from_file_location('base', A / 'анализ_файла.py')
base = importlib.util.module_from_spec(spec); spec.loader.exec_module(base)
source = ROOT / 'Firmware на прочиеFuji' / 'FPUPDATE.DAT'
sha = lambda x: hashlib.sha256(x).hexdigest()
expected = '0d48d2ae26ac7ebab9b0e4cac56324807ec1ea8ae30df06b0b9e79066dc0a14a'
raw = source.read_bytes(); before = sha(raw); assert before == expected
inverted = raw.translate(base.TRANSLATION)
b = base.unpack_fflz(inverted, 0x1402bc)
jpeg = base.unpack_fflz(inverted, 0x4402bc)
assert sha(b) == 'fbbacc6736e28c9bb44550fac0f450d8ae23b5a26e94b060c49cfc142cdbeaed'
assert sha(jpeg) == 'ca95789cdf2c7097985e3f3ae0e4feab05ca4df797919d0d1b4e4b5962613ba9'
R=0x881000; ST=0x70000000; END=0x71000000; BUF=0x72000000; CB=0x73000000

def vm():
 u=Uc(UC_ARCH_ARM64, UC_MODE_ARM); u.mem_map(R,(len(b)+4095)&~4095); u.mem_write(R,b)
 u.mem_map(R+0x254000,0x3000); u.mem_map(ST,0x10000); u.mem_map(END,0x1000); u.mem_map(BUF,0x10000); u.mem_map(CB,0x1000); u.mem_map(0x90000,0x10000)
 u.reg_write(UC_ARM64_REG_SP,ST+0xf000); u.reg_write(UC_ARM64_REG_X30,END)
 return u

def get(u,r): return u.reg_read(r)
def ret(u,v=0): u.reg_write(UC_ARM64_REG_X0,v & 0xffffffffffffffff); u.reg_write(UC_ARM64_REG_PC,get(u,UC_ARM64_REG_X30))
def put32(u,p,v): u.mem_write(p,struct.pack('<I',v))
def put64(u,p,v): u.mem_write(p,struct.pack('<Q',v))
def val32(u,p): return struct.unpack('<I',u.mem_read(p,4))[0]
def val64(u,p): return struct.unpack('<Q',u.mem_read(p,8))[0]

def messaging(value, mode, capacity, receive_status=0):
 u=vm(); slot=BUF+0x100; out=BUF+0x300; payload=BUF+0x400; trace=[]; queued=[]
 put32(u,0xad6b38+(0xea-1)*4,capacity); put64(u,0xa43080,CB)
 u.mem_write(out,bytes([0xa5])*24); put64(u,out+16,payload); u.mem_write(payload,b'\xcc'*8)
 def hook(u,pc,size,_):
  if pc in (R+0x49e0,R+0x4c10,R+0x7e80,R+0x4aa4,R+0x4cb0): trace.append(hex(pc-R))
  if pc==R+0x3d14: ret(u,0x1234)
  elif pc==CB: trace.append('callback'); ret(u)
  elif pc==0x93984: trace.append('context_mode'); ret(u,mode)
  elif pc in (0x90f88,0x9080c):
   trace.append('acquire:'+hex(pc)); put64(u,get(u,UC_ARM64_REG_X1),slot); ret(u)
  elif pc in (0x91470,0x9089c):
   trace.append('enqueue:'+hex(pc)); queued.append(bytes(u.mem_read(get(u,UC_ARM64_REG_X1),20)).hex()); ret(u)
  elif pc==0x95614:
   trace.append('dequeue');
   if not receive_status: put64(u,get(u,UC_ARM64_REG_X1),slot)
   ret(u,receive_status)
  elif pc==0x92648: trace.append('release'); ret(u)
  elif pc==0x98434 or pc==R+0x3534: trace.append('error_hook:'+hex(pc)); ret(u)
 u.hook_add(UC_HOOK_CODE,hook)
 u.reg_write(UC_ARM64_REG_X0,value); u.emu_start(R+0x1514,END,count=3000)
 assert get(u,UC_ARM64_REG_PC)==END
 send=get(u,UC_ARM64_REG_X0)&0xffffffff
 result={'value':value,'mode_synthetic':mode,'slot_capacity_synthetic':capacity,'send_return_u32':send,'queue_slot_hex':queued,'trace':trace}
 if queued:
  u.reg_write(UC_ARM64_REG_SP,ST+0xf000); u.reg_write(UC_ARM64_REG_X30,END)
  u.reg_write(UC_ARM64_REG_X0,0xea); u.reg_write(UC_ARM64_REG_X1,out); u.reg_write(UC_ARM64_REG_X2,0xffffffffffffffff)
  u.emu_start(R+0x4c10,END,count=3000); assert get(u,UC_ARM64_REG_PC)==END
  result.update(receive_status_synthetic=receive_status,receive_return_u32=get(u,UC_ARM64_REG_X0)&0xffffffff,receive_header_hex=bytes(u.mem_read(out,12)).hex(),receive_payload_hex=bytes(u.mem_read(payload,4)).hex())
 return result

def paired_messages(value, capacity=20):
 u=vm(); attempts=[]; queued=[]; trace=[]; put32(u,0xad6b38+(0xea-1)*4,capacity); put64(u,0xa43080,CB)
 def hook(u,pc,size,_):
  off=pc-R
  if off==0x49e0:
   p=get(u,UC_ARM64_REG_X1); mid=struct.unpack('<H',u.mem_read(p,2))[0]; length=val32(u,p+8)
   payload=bytes(u.mem_read(val64(u,p+16),length)).hex() if length else ''
   attempts.append({'id':hex(mid),'destination':get(u,UC_ARM64_REG_X0),'length':length,'payload_hex':payload})
  elif off in (0xb20,0xb24):
   trace.append({'offset':hex(off),'w0_u32':get(u,UC_ARM64_REG_X0)&0xffffffff})
  if off==0x3d14: ret(u,0x1234)
  elif pc==CB: ret(u)
  elif pc==0x93984: ret(u,0)
  elif pc==0x90f88:
   put64(u,get(u,UC_ARM64_REG_X1),BUF+0x100+len(queued)*0x100); ret(u)
  elif pc==0x91470:
   p=get(u,UC_ARM64_REG_X1); n=val32(u,p+8)
   queued.append({'id':hex(struct.unpack('<H',u.mem_read(p,2))[0]),'length':n,'slot_hex':bytes(u.mem_read(p,16+n)).hex()}); ret(u)
  elif pc==0x98434 or off==0x3534: ret(u)
 u.hook_add(UC_HOOK_CODE,hook); u.reg_write(UC_ARM64_REG_X0,value); u.emu_start(R+0xb0c,END,count=5000)
 assert get(u,UC_ARM64_REG_PC)==END
 return {'value':value,'capacity_synthetic':capacity,'attempts':attempts,'enqueued':queued,'intermediate_returns':trace}

def drawing(index):
 u=vm(); sourcebuf=BUF+0x1000; dst=0x40bc0000; u.mem_map(dst,0x1000)
 stride=32; u.mem_write(sourcebuf,bytes(range(32))+bytes(range(32,64))+bytes(range(64,96))); u.mem_write(dst,b'\xee'*stride)
 put32(u,R+0x254098,index); put64(u,R+0x2540a8,sourcebuf); put32(u,R+0x2540b4,stride)
 calls=[]; copied=[]
 def hook(u,pc,size,_):
  off=pc-R
  if off==0x7e80: calls.append({'offset':hex(off),'args':[hex(get(u,r)) for r in (UC_ARM64_REG_X0,UC_ARM64_REG_X1,UC_ARM64_REG_X2)]})
  if off==0x1950: copied.append(bytes(u.mem_read(dst,stride)).hex())
  if off in (0x31c6c,0x31d9c,0x32cec,0x32e0c,0x32f80,0x332b0,0x332f8,0x32bd4):
   entry={'offset':hex(off),'x0':hex(get(u,UC_ARM64_REG_X0)),'x1':hex(get(u,UC_ARM64_REG_X1)),'x2':hex(get(u,UC_ARM64_REG_X2))}; calls.append(entry)
   if off==0x31d9c: u.mem_write(get(u,UC_ARM64_REG_X2),struct.pack('<II',800,600))
   ret(u,0x60000000 if off==0x31c6c else 0)
 u.hook_add(UC_HOOK_CODE,hook); u.emu_start(R+0x18b4,END,count=5000); assert get(u,UC_ARM64_REG_PC)==END
 return {'index':index,'synthetic_stride':stride,'synthetic_source':hex(sourcebuf),'copy_result_hex':copied,'calls':calls,'destination_final_hex':bytes(u.mem_read(dst,stride)).hex()}

def initialization():
 u=vm(); calls=[]
 def hook(u,pc,size,_):
  if pc==R+0x31e58:
   calls.append({'offset':'0x31e58','x0':hex(get(u,UC_ARM64_REG_X0)),'x1':hex(get(u,UC_ARM64_REG_X1))}); ret(u)
 u.hook_add(UC_HOOK_CODE,hook); u.reg_write(UC_ARM64_REG_X0,0x12345678); u.emu_start(R+0x17e8,END,count=1000); assert get(u,UC_ARM64_REG_PC)==END
 return {'index_u32':val32(u,R+0x254098),'callback':hex(val64(u,R+0x2540a0)),'base':hex(val64(u,R+0x2540a8)),'size':val32(u,R+0x2540b0),'stride':val32(u,R+0x2540b4),'calls':calls}

def resource_descriptor():
 u=vm(); u.mem_map(0x40000000,0x1000); obj=R+0x2540b8; calls=[]
 put64(u,R+0x2540a8,0x40080000)
 def hook(u,pc,n,_):
  off=pc-R
  if off==0x19f4c:
   calls.append({'offset':hex(off),'x0':hex(get(u,UC_ARM64_REG_X0)),'x1':hex(get(u,UC_ARM64_REG_X1)),'x2':hex(get(u,UC_ARM64_REG_X2)),'x3':hex(get(u,UC_ARM64_REG_X3))})
   put32(u,0x40000030,640); put32(u,0x40000034,9120); ret(u)
  elif off==0x98778:
   calls.append({'offset':hex(off),'x0':hex(get(u,UC_ARM64_REG_X0)),'x1':hex(get(u,UC_ARM64_REG_X1))}); ret(u)
 u.hook_add(UC_HOOK_CODE,hook); u.emu_start(R+0x1a84,END,count=1000); assert get(u,UC_ARM64_REG_PC)==END
 return {'input_dimensions_synthetic':[640,9120],'object':hex(obj),'width_field':val32(u,obj+8),'height_field':val32(u,obj+12),'input_address':hex(val64(u,obj+0x18)),'input_length':val32(u,obj+0x20),'output_address':hex(val64(u,obj+0x28)),'callback':hex(val64(u,obj+0x60)),'calls':calls}

def real_jpeg_parser(corrupt_soi=False):
 u=vm(); u.mem_map(0x681000,0xa0000); source_copy=bytearray(jpeg)
 if corrupt_soi: source_copy[0]=0
 u.mem_write(0x681000,bytes(source_copy)); u.mem_map(0x40000000,0x100000)
 put64(u,R+0x2540a8,0x40080000); obj=R+0x2540b8; calls=[]; parsing=[]
 def hook(u,pc,n,_):
  off=pc-R
  if off in (0x19f4c,0x18544,0x1866c,0x19edc,0x1ab4):
   parsing.append({'offset':hex(off),'x0':hex(get(u,UC_ARM64_REG_X0)),'x1':hex(get(u,UC_ARM64_REG_X1)),'x2':hex(get(u,UC_ARM64_REG_X2)),'x3':hex(get(u,UC_ARM64_REG_X3))})
  if pc in (0x96aec,0x93984,0x93428):
   calls.append({'absolute':hex(pc),'x0':hex(get(u,UC_ARM64_REG_X0)),'x1':hex(get(u,UC_ARM64_REG_X1)),'synthetic_return':0}); ret(u)
  elif off==0x98778:
   calls.append({'offset':'0x98778','x0':hex(get(u,UC_ARM64_REG_X0)),'x1':hex(get(u,UC_ARM64_REG_X1)),'synthetic_return':0}); ret(u)
 u.hook_add(UC_HOOK_CODE,hook); u.emu_start(R+0x1a84,END,count=1000000)
 assert get(u,UC_ARM64_REG_PC)==END
 return {'modified_copy_first_byte':hex(source_copy[0]),'in_memory_input_sha256':sha(source_copy),'conditional_input_address':'0x681000','synthetic_work_address':'0x40000000','original_parser_trace':parsing,'stubbed_calls':calls,'work_width':val32(u,0x40000030),'work_height':val32(u,0x40000034),'descriptor_width':val32(u,obj+8),'descriptor_height':val32(u,obj+12),'descriptor_input':hex(val64(u,obj+0x18)),'descriptor_input_length':val32(u,obj+0x20),'descriptor_output':hex(val64(u,obj+0x28))}

def completion(size):
 u=vm(); obj=R+0x2540b8; put64(u,obj+0x30,size); calls=[]
 def hook(u,pc,n,_):
  off=pc-R
  if off in (0x987e4,0x3d14,0x49e0): calls.append(hex(off)); ret(u,0x1234 if off==0x3d14 else 0)
 u.hook_add(UC_HOOK_CODE,hook); u.emu_start(R+0x1c30,END,count=2000); assert get(u,UC_ARM64_REG_PC)==END
 return {'synthetic_result_size':size,'size':val32(u,R+0x2540b0),'stride':val32(u,R+0x2540b4),'calls':calls}

cases=[messaging(9,0,20),messaging(18,1,20),messaging(9,0,19),messaging(9,0,20,-50)]
paired=[paired_messages(i) for i in (0,10,14,18,19)]+[paired_messages(10,19)]
draw=[drawing(i) for i in (0,1,2,0xffffffff)]
init=initialization(); descriptor=resource_descriptor(); parsed=[real_jpeg_parser(False),real_jpeg_parser(True)]; complete=[completion(x) for x in (19*32,19*32+18,0)]
after=sha(source.read_bytes()); assert after==before
result={'source':str(source.relative_to(ROOT)),'source_sha256_before':before,'source_sha256_after':after,'code_fflz_dat_offset':'0x1402bc','code_sha256':sha(b),'jpeg_fflz_dat_offset':'0x4402bc','jpeg_sha256':sha(jpeg),'jpeg_size':len(jpeg),'conditional_base':hex(R),'message_cases':cases,'paired_message_cases':paired,'initialization':init,'resource_descriptor':descriptor,'real_jpeg_parser_cases':parsed,'completion_cases':complete,'drawing_cases':draw,'caveat':'VM only; synthetic lower queue, callback and graphics APIs; no physical camera or JPEG pixel decoding.'}
(HERE/'результаты.json').write_text(json.dumps(result,ensure_ascii=False,indent=2)+'\n',encoding='utf-8')
print(json.dumps(result,ensure_ascii=False,indent=2))
