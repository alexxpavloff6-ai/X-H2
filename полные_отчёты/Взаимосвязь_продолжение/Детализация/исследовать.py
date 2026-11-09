"""Original A64 parameter-preparation fragments, isolated synthetic state; no ISP."""
from pathlib import Path
import hashlib, importlib.util, json, struct, sys
from unicorn import Uc, UC_ARCH_ARM64, UC_MODE_ARM, UC_HOOK_CODE
from unicorn.arm64_const import UC_ARM64_REG_X19, UC_ARM64_REG_X20, UC_ARM64_REG_SP, UC_ARM64_REG_PC
from capstone import Cs, CS_ARCH_ARM64, CS_MODE_LITTLE_ENDIAN

HERE = Path(__file__).resolve().parent
A = HERE.parents[1]
sys.path.insert(0, str(A / 'инструменты'))
spec = importlib.util.spec_from_file_location('tables', A / 'Единый_глубокий_анализ/сопоставить_таблицы.py')
tables = importlib.util.module_from_spec(spec); spec.loader.exec_module(tables)
# sharp start, NR start/end, clarity start/end, parameter offsets sharp/NR/clarity
CONFIG = {
 'X-H2': (0x2e62f14,0x2e62f4c,0x2e62f84,0x2e634c0,0x2e634fc,0x39b0,0x39d8,0x3f34),
 'X-H2S':(0x3179e78,0x3179eb0,0x3179ee8,0x317a424,0x317a460,0x3954,0x397c,0x3ee0),
 'X-T5':(0x2da14a8,0x2da14e0,0x2da1518,0x2da1a64,0x2da1d0c,0x39f8,0x3a20,0x3f6c),
 'X100VI':(0x3071bc0,0x3071bf8,0x3071c34,0x3072194,0x3072440,0x3fe0,0x4008,0x4560),
}
CONTEXT = {
 'X-H2': (0x2e623f4,0x2e1e128),
 'X-H2S':(0x3179358,0x3136704),
 'X-T5':(0x2da0948,0x2d5b9c8),
 'X100VI':(0x307104c,0x3027478),
}
PARAM, OUT, STACK = 0x60000000,0x60010000,0x70000000
md=Cs(CS_ARCH_ARM64,CS_MODE_LITTLE_ENDIAN)
results={}
for name,c in CONFIG.items():
 sharp,nr,nrend,clar,clarend,so,no,co=c
 rel,expected,ao,bo,*_=tables.FILES[name]; path=A.parent/rel
 raw=path.read_bytes(); before=hashlib.sha256(raw).hexdigest()
 if before != expected: raise RuntimeError(f'{name}: unexpected DAT hash {before}')
 decoded=raw.translate(tables.base.TRANSLATION); images=[]
 for off in (ao,bo):
  data=tables.base.unpack_fflz(decoded,off); images.append((struct.unpack_from('<Q',data,8)[0],data))
 u=Uc(UC_ARCH_ARM64,UC_MODE_ARM);u.mem_map(images[0][0],0x6000000-images[0][0])
 for base,data in images: u.mem_write(base,data)
 u.mem_map(PARAM,0x20000);u.mem_map(STACK,0x10000)
 trace=[]; called=[]
 def hook(uc,address,size,_):
  rawins=bytes(uc.mem_read(address,4)); ins=next(md.disasm(rawins,address),None)
  trace.append({'address':hex(address),'bytes':rawins.hex(),'instruction':f'{ins.mnemonic} {ins.op_str}' if ins else 'undecoded'})
  # Unsupported values reach a diagnostic BL. Stop at the call, not a fabricated return.
  if ins and ins.mnemonic in ('bl','blr'):
   called.append(hex(address));uc.emu_stop()
 u.hook_add(UC_HOOK_CODE,hook)
 cases=[]
 for kind,start,end,offset,outoff,values in (
  ('sharp',sharp,nr,so,0x249,list(range(10))),
  ('nr',nr,nrend,no,0x24d,list(range(10))),
  ('clarity',clar,clarend,co,0x269,list(range(-6,7)))):
  for value in values:
   for other in (False,True):
    u.mem_write(PARAM,bytes(0x8000));u.mem_write(OUT,b'\xa5'*0x1000)
    for off,v in ((so,4),(no,4),(co,0)):
     u.mem_write(PARAM+off,struct.pack('<I',v))
    if other:
     # Deliberately change the two unrelated inputs, leaving tested input unchanged.
     for off,v in ((so,3),(no,0),(co,3)):
      if off!=offset:u.mem_write(PARAM+off,struct.pack('<I',v))
    u.mem_write(PARAM+offset,struct.pack('<I',value & 0xffffffff))
    u.reg_write(UC_ARM64_REG_X19,OUT);u.reg_write(UC_ARM64_REG_X20,PARAM);u.reg_write(UC_ARM64_REG_SP,STACK+0xf000)
    trace.clear();called.clear();u.emu_start(start,end,count=10000)
    data=bytes(u.mem_read(OUT+outoff,4))
    pc=u.reg_read(UC_ARM64_REG_PC)
    cases.append({'kind':kind,'input':value,'other_fields_changed':other,'start':hex(start),'stop':hex(end),'actual_pc':hex(pc),'status':'stopped_before_call' if called else ('reached_stop' if pc==end else 'instruction_limit'),'call':called[:],'output_bytes':data.hex(' '),'output_s32':struct.unpack('<i',data)[0], 'trace':trace[:]})
 after=hashlib.sha256(path.read_bytes()).hexdigest()
 if before!=after:raise RuntimeError(f'{name}: DAT changed')
 fn,call=CONTEXT[name]
 def listing(start,size):
  return [{'address':hex(i.address),'bytes':i.bytes.hex(),'instruction':f'{i.mnemonic} {i.op_str}'} for i in md.disasm(bytes(u.mem_read(start,size)),start)]
 results[name]={'dat':str(rel),'sha256_before':before,'sha256_after':after,'images':[{'base':hex(b),'size':len(d),'sha256':hashlib.sha256(d).hexdigest()} for b,d in images], 'function':hex(fn),'function_prologue':listing(fn,0x30),'caller_window':listing(call-20,0x44),'input_offsets':{'sharp':hex(so),'nr':hex(no),'clarity':hex(co)},'output_offsets':{'sharp':'0x249','nr':'0x24d','clarity':'0x269'},'cases':cases}
(HERE/'результаты.json').write_text(json.dumps({'method':'Isolated original A64 fragments; synthetic parameter and destination buffers. Stop before diagnostic calls; no simulated ISP or camera. No chaining to metadata writers.', 'cameras':results},ensure_ascii=False,indent=2)+'\n',encoding='utf-8')
