"""Original firmware fragments on artificial RAM; not an actual camera pipeline."""
from pathlib import Path
import hashlib, importlib.util, json, struct, sys
from unicorn import Uc, UC_ARCH_ARM64, UC_MODE_ARM
from unicorn.arm64_const import UC_ARM64_REG_X0, UC_ARM64_REG_X1, UC_ARM64_REG_X2, UC_ARM64_REG_X3, UC_ARM64_REG_X19, UC_ARM64_REG_X20, UC_ARM64_REG_X30, UC_ARM64_REG_SP, UC_ARM64_REG_PC
from capstone import Cs, CS_ARCH_ARM64, CS_MODE_LITTLE_ENDIAN
HERE = Path(__file__).resolve().parent
A = HERE.parents[2]
sys.path.insert(0, str(A / 'инструменты'))
spec = importlib.util.spec_from_file_location('tables', A / 'Единый_глубокий_анализ/сопоставить_таблицы.py')
t = importlib.util.module_from_spec(spec); spec.loader.exec_module(t)
# sat writer, chrome start/end, gate, chrome fields, WB mode, shift, regular Kelvin field,
# alternate-source discriminator, selector, three alternate Kelvin fields, builder, predicate, group table
C = {
'X-H2': (0x2e52cbc,0x2e531d0,0x2e53208,0x3978,0x3f10,0x3f14,0x39a4,0x39a8,0x3a94,0x396c,0x429c,0x4160,0x13503e4,0x134df8c,0x18d3dc8),
'X-H2S': (0x3169fa0,0x316a4b4,0x316a4ec,0x391c,0x3ebc,0x3ec0,0x3948,0x394c,0x3a40,0x390c,0x424c,0x4114,0x166dfc4,0x166bb6c,0x1bf0fa0),
'X-T5': (0x2d90f04,0x2d91410,0x2d91468,0x39c0,0x3f48,0x3f4c,0x39ec,0x39f0,0x3ad0,0x39b4,0x4418,0x42d0,0x134d3b4,0x134af5c,0x18d1650),
'X100VI': (0x3060e3c,0x3061370,0x30613d0,0x3fa8,0x4538,0x453c,0x3fd4,0x3fd8,0x40c0,0x3f9c,0x4a50,0x48e8,0x14376ac,0x14350f8,0x19ca6a8)}
P,O,B,S = 0x60000000,0x60010000,0x60020000,0x70000000
REGS = (UC_ARM64_REG_X0, UC_ARM64_REG_X1, UC_ARM64_REG_X2, UC_ARM64_REG_X3)
TAGS = {0x1002:(3,1),0x1005:(3,1),0x100a:(9,2),0x1048:(9,1),0x104e:(9,1)}
md=Cs(CS_ARCH_ARM64, CS_MODE_LITTLE_ENDIAN)
result={'method':'Unpatched original per-camera ARM64; zero-filled artificial RAM, manually joined writer fragments, predicate and builder. No UI or JPEG pipeline.','cameras':{}}
for name,c in C.items():
 sat,start,end,gate,chrome,blue,mode,shift,temp,disc,sel,alt,builder,pred,table=c
 rel,expected,ao,bo,*_=t.FILES[name]; path=A.parent/rel
 raw=path.read_bytes(); before=hashlib.sha256(raw).hexdigest(); assert before==expected
 data=raw.translate(t.base.TRANSLATION); a=t.base.unpack_fflz(data,ao); b=t.base.unpack_fflz(data,bo)
 ba,bb=struct.unpack_from('<Q',a,8)[0],struct.unpack_from('<Q',b,8)[0]
 uc=Uc(UC_ARCH_ARM64,UC_MODE_ARM); uc.mem_map(ba,0x6000000-ba); uc.mem_write(ba,a); uc.mem_write(bb,b); uc.mem_map(P,0x30000); uc.mem_map(S,0x10000)
 def call(pc,args=(),stop=S,extra=()):
  for r,v in zip(REGS,args): uc.reg_write(r,v)
  for r,v in extra: uc.reg_write(r,v)
  uc.reg_write(UC_ARM64_REG_X30,S); uc.reg_write(UC_ARM64_REG_SP,S+0xf000)
  uc.emu_start(pc,stop,count=1000000); assert uc.reg_read(UC_ARM64_REG_PC)==stop
  return uc.reg_read(UC_ARM64_REG_X0)
 def case(ch,bl,mo,r,blu,k, g=2, d=0, selector=0):
  uc.mem_write(P,bytes(0x5000)); uc.mem_write(O,bytes(0x10000)); uc.mem_write(B,bytes(0x10000))
  for off,val in ((gate,g),(chrome,ch),(blue,bl),(mode,mo),(shift,r),(shift+4,blu),(disc,d)):
   uc.mem_write(P+off,struct.pack('<I',val & 0xffffffff))
  for off,val in ((temp,k),(sel,selector),(alt,5100),(alt+2,5200),(alt+4,5300)):
   uc.mem_write(P+off,struct.pack('<H',val))
  extra=((UC_ARM64_REG_X19,P),(UC_ARM64_REG_X20,O))
  call(sat-0x18,stop=sat+0x70,extra=extra)
  call(start,stop=end,extra=extra)
  region=bytes(uc.mem_read(O,0xb0))
  ps={f'{tag:04x}':call(pred,(2,tag,O)) for tag in TAGS}
  length=call(builder,(2,O,B,B)); assert length<=0x10000
  buf=bytes(uc.mem_read(B,length)); records={}
  for tag,(typ,cnt) in TAGS.items():
   prefix=struct.pack('<HHI',tag,typ,cnt)
   hits=[i for i in range(len(buf)-11) if buf[i:i+8]==prefix]
   records[f'{tag:04x}']=[{'offset':i,'entry_hex':buf[i:i+12].hex(' '), 'pointed_data_hex':buf[struct.unpack_from('<I',buf,i+8)[0]:][:cnt*4].hex(' ') if cnt==2 else None} for i in hits]
  return {'inputs':{'chrome':ch,'blue':bl,'mode':mo,'shift':[r,blu],'kelvin_field':k,'gate':g,'discriminator':d,'alternate_selector':selector}, 'object':{'chrome':struct.unpack_from('<i',region,0x4c)[0],'blue':struct.unpack_from('<i',region,0x50)[0],'mode':struct.unpack_from('<H',region,0x98)[0],'temperature':struct.unpack_from('<H',region,0x9e)[0],'shift':list(struct.unpack_from('<ii',region,0xa4))},'predicates':ps,'directory_length':length,'records':records}
 cases=[case(0,0,13,0,0,5750),case(2,2,13,1,-5,5750),case(1,2,13,0,0,5750),case(2,1,13,0,0,5750),case(3,3,13,0,0,5750),case(2,2,0,1,-5,5750),case(2,2,13,1,-5,5750,d=10,selector=2),case(2,2,13,1,-5,5750,d=10,selector=3)]
 shifts=[case(0,0,13,v,v,5750)['object']['shift'] for v in range(-10,11)]
 descriptors={}
 for i in range(150):
  x=bytes(uc.mem_read(table+i*40,40)); tag=struct.unpack_from('<H',x)[0]
  if tag in TAGS: descriptors[f'{tag:04x}']={'address':hex(table+i*40),'bytes':x.hex(' '),'source_offset':hex(struct.unpack_from('<I',x,32)[0])}
 def ins(st,en): return [f'{i.address:08x} {i.bytes.hex(" ")} {i.mnemonic} {i.op_str}' for i in md.disasm(b[st-bb:en-bb],st)]
 after=hashlib.sha256(path.read_bytes()).hexdigest(); assert before==after
 result['cameras'][name]={'dat':str(rel),'sha256_before':before,'sha256_after':after,'offsets':dict(zip(('gate','chrome','blue','wb_mode','wb_shift','kelvin','discriminator','selector','alternate_kelvin'),map(hex,(gate,chrome,blue,mode,shift,temp,disc,sel,alt)))),'descriptors':descriptors,'writer_start':hex(sat-0x18),'chrome_start':hex(start),'chrome_end':hex(end),'cases':cases,'shift_scan_minus10_to_10':shifts,'disassembly':{'wb_writer':ins(sat-0x18,sat+0x70),'chrome_main':ins(start,end)}}
(HERE/'результаты.json').write_text(json.dumps(result,ensure_ascii=False,indent=2)+'\n',encoding='utf-8')
print(json.dumps({n:v['cases'] for n,v in result['cameras'].items()},ensure_ascii=False,indent=2))
