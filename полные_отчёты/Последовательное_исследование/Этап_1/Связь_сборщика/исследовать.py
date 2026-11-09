"""Трассировка владельцев MakerNote, виртуальные адреса X-H2 5.30; входы только читаются."""
from pathlib import Path
import hashlib, importlib.util, json, struct, sys

HERE=Path(__file__).resolve().parent
ROOT=HERE.parents[2]
sys.path.insert(0,str(ROOT/'инструменты'))
from capstone import Cs, CS_ARCH_ARM64, CS_MODE_LITTLE_ENDIAN
spec=importlib.util.spec_from_file_location('prior',ROOT/'Рецепты/Цветовые_этапы_31.10.2026/проверить_цветовые_этапы.py')
prior=importlib.util.module_from_spec(spec); spec.loader.exec_module(prior)
inputs=[('FIRMWARE/ver 5.30/FWUP0028.DAT','be47168cb075ef726e67cb4bb08175a896047a3b0de2bcb6e65333b22cfcb203'),('Firmware на прочиеFuji/FWUP0027.DAT','87c566c1ff6343e4c7463a4ef968183f41d1f24cc63d610433d3a387b13f731b'),('Firmware на прочиеFuji/FWUP0030.DAT','790d6deecf26766188b0e506e40645e6b816addfeba39a52334349405421724e'),('Firmware на прочиеFuji/FPUPDATE.DAT','0d48d2ae26ac7ebab9b0e4cac56324807ec1ea8ae30df06b0b9e79066dc0a14a')]
def digest(p):
    h=hashlib.sha256()
    with p.open('rb') as f:
        for chunk in iter(lambda:f.read(1024*1024),b''): h.update(chunk)
    return h.hexdigest()
before={p:digest(ROOT.parent/p) for p,_ in inputs}
assert all(before[p]==v for p,v in inputs)
x=prior.Study(); blocks=[(x.a,0x1101000),(x.b,0x29ae000)]
md=Cs(CS_ARCH_ARM64,CS_MODE_LITTLE_ENDIAN)
def dis(a,b):
    for data,base in blocks:
        if base<=a and b<=base+len(data):
            return [{'address':hex(i.address),'bytes':i.bytes.hex(' '),'instruction':i.mnemonic+' '+i.op_str} for i in md.disasm(data[a-base:b-base],a)]
    raise ValueError(hex(a))
def calls(target):
    out=[]
    for data,base in blocks:
        for off in range(0,len(data)-3,4):
            w=struct.unpack_from('<I',data,off)[0]
            if w>>26==0x25:
                d=w&0x3ffffff
                if d&0x2000000: d-=0x4000000
                if base+off+4*d==target: out.append(hex(base+off))
    return out
ranges=[(0x133f300,0x133f7c0),(0x2e7a704,0x2e7aa00),(0x2dde450,0x2ddeb00),(0x2de3b40,0x2de3c80),(0x2e50b14,0x2e50c80),(0x134cdf8,0x134d120),(0x1340a80,0x13411b0),(0x13414c0,0x13416d0),(0x2e76010,0x2e76110),(0x2e668b4,0x2e66b80),(0x2e99000,0x2e992b0)]
targets=(0x13503e4,0x2e54f84,0x2e51d48,0x2f1d10c,0x133f5d4,0x2e7a704,0x134cdf8,0x134cea8,0x1340c5c,0x134161c,0x2e668b4,0x2dde56c)
def pointers(target):
    out=[]
    needle=struct.pack('<Q',target)
    for data,base in blocks:
        start=0
        while True:
            off=data.find(needle,start)
            if off<0: break
            out.append(hex(base+off)); start=off+1
    return out
result={'input_sha256_before':before,'contexts':{f'{a:#x}..{b:#x}':dis(a,b) for a,b in ranges},'direct_bl':{hex(a):calls(a) for a in targets},'pointer_constants':{hex(a):pointers(a) for a in targets}}
from unicorn import UC_HOOK_CODE
from unicorn.arm64_const import UC_ARM64_REG_X0, UC_ARM64_REG_X1, UC_ARM64_REG_X3, UC_ARM64_REG_X4, UC_ARM64_REG_X25
for addr in (0x260c000,0x2430000,0x229b000,0x2055000,0x253a000):
    x.uc.mem_map(addr,0x1000)
params,owner,buf,holder,scratch=0x60000000,0x60010000,0x60030000,0x6003e000,0x6003f000
obj=owner+0x3da4
seen=[]
def on_builder(uc,address,size,user):
    seen.append({'group':uc.reg_read(UC_ARM64_REG_X0),'object':hex(uc.reg_read(UC_ARM64_REG_X1))})
x.uc.hook_add(UC_HOOK_CODE,on_builder,begin=0x13503e4,end=0x13503e4)
cases=[]
for mode in (13,19,22,4):
    x.clear(params,0x8000); x.clear(owner,0x16000); x.clear(buf,0x10000)
    for addr in (0x260c000,0x2430000,0x229b000,0x2055000,0x253a000): x.clear(addr)
    def q(addr,value): x.uc.mem_write(addr,struct.pack('<Q',value))
    q(holder+8,buf); q(0x24309e0,buf); q(0x2430a10,scratch); q(0x2430a08,scratch+8); q(0x2430a18,buf)
    x.uc.mem_write(0x2430a70,struct.pack('<H',1))
    x.word(params+0x3978,2); x.word(params+0x39b8,mode)
    # Реальные куски одного вызывающего; остановки перед BL, не моделируется соседний вызов 0x2e50b14.
    x.run(0x2dde738,until=0x2dde744,registers={21:owner})
    x.run(0x2dde79c,until=0x2dde7b4)
    writer_arg=x.uc.reg_read(UC_ARM64_REG_X4)
    x.run(0x2e537c8,until=0x2e537e4,registers={19:params,20:writer_arg})
    x.run(0x2ddea1c,until=0x2ddea40,registers={21:owner,25:holder,28:owner+0x5a0,19:owner+0x128ac})
    helper_arg=x.uc.reg_read(UC_ARM64_REG_X3)
    x.run(0x2dde594,until=0x2dde5a4,registers={3:helper_arg})
    saved=x.uc.reg_read(UC_ARM64_REG_X25)
    x.run(0x2dde5f4,until=0x2dde5fc,registers={25:saved,20:buf})
    wrapper_arg=x.uc.reg_read(UC_ARM64_REG_X0)
    seen.clear()
    n=x.run(0x1340c5c,[wrapper_arg,buf])
    data=bytes(x.uc.mem_read(buf,n))
    prefix=bytes.fromhex('01 14 03 00 01 00 00 00')
    offsets=[i for i in range(len(data)-11) if data[i:i+8]==prefix]
    cases.append({'mode':mode,'writer_x4':hex(writer_arg),'helper_x3':hex(helper_arg),'wrapper_x0':hex(wrapper_arg),'builder':list(seen),'flag':x.u32(obj+0x18c),'value':bytes(x.uc.mem_read(obj+0x190,2)).hex(' '),'output_length':n,'record_offsets':offsets,'records':[data[i:i+12].hex(' ') for i in offsets]})
result['vm']={'cases':cases,'scope':'Artificial RAM; separate real fragments; manually skipped intervening execution including 0x2e50b14; full wrapper 0x1340c5c and builder, not complete capture.'}
after={p:digest(ROOT.parent/p) for p,_ in inputs}
assert before==after
result['input_sha256_after']=after
(HERE/'результат.json').write_text(json.dumps(result,ensure_ascii=False,indent=2)+'\n',encoding='utf-8')
print(json.dumps(result['direct_bl'],indent=2))
