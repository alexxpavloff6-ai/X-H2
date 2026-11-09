"""Run original ARM64 detail-setting fragments independently on synthetic RAM."""
from pathlib import Path
import hashlib
import importlib.util
import json
import struct
import sys

HERE = Path(__file__).resolve().parent
ANALYSIS = HERE.parents[2]
sys.path.insert(0, str(ANALYSIS / 'инструменты'))
spec = importlib.util.spec_from_file_location('tables', ANALYSIS / 'Единый_глубокий_анализ/сопоставить_таблицы.py')
tables = importlib.util.module_from_spec(spec)
spec.loader.exec_module(tables)
from unicorn import Uc, UC_ARCH_ARM64, UC_MODE_ARM
from unicorn.arm64_const import UC_ARM64_REG_X0, UC_ARM64_REG_X19, UC_ARM64_REG_X20, UC_ARM64_REG_X30, UC_ARM64_REG_SP
from capstone import Cs, CS_ARCH_ARM64, CS_MODE_LITTLE_ENDIAN

# Three caller fragments, their corresponding functions, gate and input offsets,
# group-2 selector, builder, predicate.
CONFIG = {
 'X-H2': (0x2e52c98,0x2e52d38,0x2e52d44,0x2e50d20,0x2e514c8,0x2e5151c,0x3978,0x39b0,0x39d8,0x3f34,0x134fd68,0x13503e4,0x134df8c),
 'X-H2S': (0x3169f7c,0x316a01c,0x316a028,0x3168010,0x31687b0,0x3168804,0x391c,0x3954,0x397c,0x3ee0,0x166d948,0x166dfc4,0x166bb6c),
 'X-T5': (0x2d90ee0,0x2d90f80,0x2d90f8c,0x2d8ee58,0x2d8f650,0x2d8f6a4,0x39c0,0x39f8,0x3a20,0x3f6c,0x134cd38,0x134d3b4,0x134af5c),
 'X100VI': (0x3060e18,0x3060eb8,0x3060ec4,0x305ee00,0x305f600,0x305f654,0x3fa8,0x3fe0,0x4008,0x4560,0x1437030,0x14376ac,0x14350f8),
}
PARAM, OBJ, BUF, STACK, STOP = 0x60000000, 0x60010000, 0x60020000, 0x70000000, 0x70000000
TAGS = {0x1001:(3,0x42,2), 0x100e:(3,0xb8,2), 0x100f:(9,0xbc,4)}
md = Cs(CS_ARCH_ARM64, CS_MODE_LITTLE_ENDIAN)

def vm(images):
 u = Uc(UC_ARCH_ARM64, UC_MODE_ARM)
 u.mem_map(images[0][0], 0x6000000-images[0][0])
 for base, data in images: u.mem_write(base, data)
 u.mem_map(PARAM, 0x30000)
 u.mem_map(STACK, 0x10000)
 return u

def run(u, start, args=(), end=STOP):
 for i,v in enumerate(args): u.reg_write(UC_ARM64_REG_X0+i,v)
 u.reg_write(UC_ARM64_REG_X30, STOP)
 u.reg_write(UC_ARM64_REG_SP, STACK+0xf000)
 u.emu_start(start, end, count=2000000)
 return u.reg_read(UC_ARM64_REG_X0)

def put(u, addr, value): u.mem_write(addr, struct.pack('<I',value & 0xffffffff))
def instr(images, start, length):
 base, data = images[1]
 return [f'{i.address:08x} {i.bytes.hex(" ")} {i.mnemonic} {i.op_str}' for i in md.disasm(data[start-base:start-base+length],start)]
def record(data, tag, typ):
 prefix=struct.pack('<HHI',tag,typ,1)
 return [{'offset': i, 'bytes':data[i:i+12].hex(' ')} for i in range(len(data)-11) if data[i:i+8]==prefix]

results = {}
for name,c in CONFIG.items():
 sharp, nr, clarity, sharp_fn, nr_fn, clarity_fn, gate, so, no, co, selector, builder, pred = c
 rel, expected, ao, bo, *_ = tables.FILES[name]
 path = ANALYSIS.parent / rel
 raw = path.read_bytes(); before = hashlib.sha256(raw).hexdigest()
 if before != expected: raise RuntimeError(f'{name}: unexpected hash {before}')
 decoded = raw.translate(tables.base.TRANSLATION)
 images=[]
 for off in (ao,bo):
  data=tables.base.unpack_fflz(decoded,off)
  images.append((struct.unpack_from('<Q',data,8)[0],data))
 u=vm(images); table=run(u,selector,[2]); descriptors={}
 for i in range(256):
  addr=table+40*i; data=bytes(u.mem_read(addr,40)); tag,typ,count=struct.unpack_from('<H2xHI',data)
  if tag in TAGS and typ==TAGS[tag][0] and count==1:
   descriptors[f'{tag:04x}']={'address':hex(addr),'bytes':data.hex(' '),'offset':struct.unpack_from('<Q',data,32)[0]}
 if len(descriptors)!=3: raise RuntimeError(f'{name}: missing descriptors {descriptors}')

 # Each fragment gets a fresh VM, A5 object, one independent parameter. No
 # fragment output is fed into a different fragment or the separate builder.
 cases=[]
 for label,start,end,offset,objoff,size,values in (
  ('sharp',sharp,sharp+12,so,0x42,2,[4,3,0,8,9,0xffffffff]),
  ('nr',nr,nr+12,no,0xb8,2,[4,0,8,9,0xffffffff]),
  ('clarity',clarity,clarity+12,co,0xbc,4,[0,3,-5,5,6,-6])):
  for value in values:
   for g in (2,46):
    v=vm(images);v.mem_write(OBJ,bytes([0xa5])*0x400);put(v,PARAM+gate,g);put(v,PARAM+offset,value)
    v.reg_write(UC_ARM64_REG_X19,PARAM);v.reg_write(UC_ARM64_REG_X20,OBJ)
    run(v,start,end=end)
    cases.append({'kind':label,'gate':g,'input':value,'object_value_bytes':bytes(v.mem_read(OBJ+objoff,size)).hex(' '),'nr_flag_bytes':bytes(v.mem_read(OBJ+0xb4,4)).hex(' ') if label=='nr' else None})
 # Separate builder experiment: independently populate the descriptor fields,
 # not outputs from the fragments. The flags are explicitly set by the analyst.
 builders=[]
 for label,sh,n,cl,flag in [('neutral',3,0,0,1),('recipe',130,736,3000,1),('nr_flag_zero',130,736,3000,0),('sharp_sentinel',65535,736,3000,1)]:
  v=vm(images);v.mem_write(OBJ+0x42,struct.pack('<H',sh));v.mem_write(OBJ+0xb8,struct.pack('<H',n));put(v,OBJ+0xbc,cl);put(v,OBJ+0xb4,flag)
  predicates={f'{tag:04x}':run(v,pred,[2,tag,OBJ]) for tag in TAGS}
  length=run(v,builder,[2,OBJ,BUF,BUF]);data=bytes(v.mem_read(BUF,length))
  builders.append({'case':label,'manually_seeded':{'sharp':sh,'nr':n,'clarity':cl,'nr_flag':flag},'predicates':predicates,'length':length,'records':{f'{tag:04x}':record(data,tag,typ) for tag,(typ,_,_) in TAGS.items()}})
 after=hashlib.sha256(path.read_bytes()).hexdigest()
 if after!=before: raise RuntimeError(f'{name}: DAT changed')
 results[name]={'dat':str(rel),'sha256_before':before,'sha256_after':after,'images':[{'base':hex(b),'length':len(d),'sha256':hashlib.sha256(d).hexdigest()} for b,d in images], 'gate_offset':hex(gate),'input_offsets':{'sharp':hex(so),'nr':hex(no),'clarity':hex(co)},'fragments':{'sharp':hex(sharp),'nr':hex(nr),'clarity':hex(clarity)},'functions':{'sharp':hex(sharp_fn),'nr':hex(nr_fn),'clarity':hex(clarity_fn)},'builder':hex(builder),'predicate':hex(pred),'descriptors':descriptors,'fragment_cases':cases,'builder_cases':builders,'disassembly':{'sharp_caller':instr(images,sharp,12),'nr_caller':instr(images,nr,12),'clarity_caller':instr(images,clarity,12),'sharp_function':instr(images,sharp_fn,0xe0),'nr_function':instr(images,nr_fn-0x78,0xcc),'clarity_function':instr(images,clarity_fn,0xd0)}}
(HERE/'результаты.json').write_text(json.dumps({'method':'Independent original caller fragments and separately manually seeded builder; no fragment chaining. Artificial RAM; no pixels or camera state.', 'cameras':results},ensure_ascii=False,indent=2)+'\n',encoding='utf-8')
print(json.dumps({n:{'fragment_cases':len(v['fragment_cases']),'builder_cases':v['builder_cases']} for n,v in results.items()},ensure_ascii=False,indent=2))
