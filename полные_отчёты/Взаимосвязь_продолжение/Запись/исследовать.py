"""Локальный анализ буферного пути; исходные DAT только читаются."""
from pathlib import Path
import sys, importlib.util, hashlib, struct, json
sys.dont_write_bytecode = True
HERE = Path(__file__).resolve().parent
ROOT = HERE.parents[2]
AN = ROOT / 'Анализ_прошивки'
spec = importlib.util.spec_from_file_location('prior', AN / 'Полная_взаимосвязь/RAW_JPEG/исследовать.py')
prior = importlib.util.module_from_spec(spec); spec.loader.exec_module(prior)
import numpy as np
from unicorn import Uc, UC_ARCH_ARM64, UC_MODE_ARM, UC_HOOK_CODE, UcError
from unicorn.arm64_const import UC_ARM64_REG_X0, UC_ARM64_REG_X1, UC_ARM64_REG_X2, UC_ARM64_REG_X30, UC_ARM64_REG_SP, UC_ARM64_REG_PC

def digest(p):
    h = hashlib.sha256()
    with p.open('rb') as f:
        for chunk in iter(lambda: f.read(1048576), b''): h.update(chunk)
    return h.hexdigest()

def calls(regions, target):
    found = []
    for base, data in regions:
        w = np.frombuffer(data[:len(data)//4*4], dtype='<u4')
        ids = np.nonzero((w & 0xfc000000) == 0x94000000)[0]
        imm = (w[ids] & 0x03ffffff).astype(np.int64)
        imm[imm >= (1 << 25)] -= 1 << 26
        for i in ids[(base + ids.astype(np.int64)*4 + imm*4) == target]: found.append(base + int(i)*4)
    return found

def literal_refs(regions, target):
    result={}
    for size in (4,8):
        needle=target.to_bytes(size,'little'); hits=[]
        for base,data in regions:
            p=0
            while True:
                p=data.find(needle,p)
                if p<0: break
                if p % size == 0: hits.append(hex(base+p))
                p+=1
        result[str(size)]=hits
    return result

def semantic(regions):
    # Регистры и смещения загрузок намеренно не фиксируются. Проверяются классы
    # четырёх ldr, затем sub/add/cmp; это поисковый кандидат, не доказательство.
    masks = [(0xffc00000,0xf9400000),(0xffc00000,0xf9400000),
             (0xffc00000,0xb9400000),(0xffc00000,0xb9400000),
             (0xff200000,0xcb000000),(0xff200000,0x8b000000),(0xff20001f,0xeb00001f)]
    out=[]
    for base,data in regions:
        w=np.frombuffer(data[:len(data)//4*4], dtype='<u4'); n=len(w)-len(masks)+1
        ok=np.ones(n,dtype=bool)
        for j,(mask,value) in enumerate(masks): ok &= (w[j:j+n] & mask)==value
        out.extend(base+int(i)*4 for i in np.nonzero(ok)[0])
    return out

def vm(regions, start, stop, capacity, field_delta=0, trace_calls=False, reserve=0x80):
    u=Uc(UC_ARCH_ARM64,UC_MODE_ARM);u.mem_map(0x40000,0x5fc0000)
    for a,b in regions: u.mem_write(a,b)
    u.mem_map(0x70000000,0x50000)
    u.mem_map(0x70050000,0x10000)
    dst=0x70050000
    src=bytes((0x21+7*i)&255 for i in range(48)); initial=bytes([0xa5])*0x5000
    u.mem_write(dst,initial);u.mem_write(0x70002000,src)
    obj=0x70010000
    u.mem_write(obj+0x13270+field_delta,struct.pack('<Q',0x70002000))
    u.mem_write(obj+0x13278+field_delta,struct.pack('<I',reserve))
    u.mem_write(obj+0x13280+field_delta,struct.pack('<Q',0x70003000))
    u.mem_write(obj+0x13288+field_delta,struct.pack('<I',0))
    u.mem_write(obj+0x13290+field_delta,struct.pack('<Q',0x70002030))
    u.mem_write(0x70030000,struct.pack('<I',capacity))
    u.reg_write(UC_ARM64_REG_X0,dst);u.reg_write(UC_ARM64_REG_X1,0x70030000);u.reg_write(UC_ARM64_REG_X2,obj)
    u.reg_write(UC_ARM64_REG_SP,0x7004f000);u.reg_write(UC_ARM64_REG_X30,0x70040000)
    trace=[]; call_trace=[]
    def hook(uc,addr,size,user):
        if trace_calls and len(call_trace)<3000:
            word=int.from_bytes(uc.mem_read(addr,4),'little')
            if word & 0xfc000000 == 0x94000000:
                imm=word & 0x3ffffff
                if imm & 0x2000000: imm-=0x4000000
                call_trace.append({'pc':hex(addr),'target':hex(addr+imm*4),
                                   'x0':hex(uc.reg_read(UC_ARM64_REG_X0)),
                                   'x1':hex(uc.reg_read(UC_ARM64_REG_X1)),
                                   'x2':hex(uc.reg_read(UC_ARM64_REG_X2))})
        if addr in stop or addr==0x70040000:
            trace.append({'pc':hex(addr),'x0':hex(uc.reg_read(UC_ARM64_REG_X0)),'x1':hex(uc.reg_read(UC_ARM64_REG_X1)),'x2':hex(uc.reg_read(UC_ARM64_REG_X2))});uc.emu_stop()
    u.hook_add(UC_HOOK_CODE,hook)
    error=None
    try: u.emu_start(start,0,count=1000000)
    except UcError as e: error=str(e)
    out=bytes(u.mem_read(dst,len(initial)))
    return {'capacity':capacity,'reserve':reserve,'output_address':hex(dst),'stop':hex(u.reg_read(UC_ARM64_REG_PC)),'boundary':trace,'error':error,'calls':call_trace,'first_48_match':out[:48]==src,'unchanged':out==initial,'output_sha256':hashlib.sha256(out).hexdigest(),'source_hex':src.hex(),'capacity_after':int.from_bytes(u.mem_read(0x70030000,4),'little')}

def main():
    before={name:digest(ROOT/filename) for name,filename,*_ in prior.MODELS}
    results=[]
    for name,filename,expected,offsets,starts in prior.MODELS:
        if before[name]!=expected: raise ValueError('DAT SHA256 mismatch: '+name)
        raw=(ROOT/filename).read_bytes().translate(prior.base.TRANSLATION)
        blocks=[]
        for off,addr in zip(offsets,starts):
            b=prior.base.unpack_fflz(raw,off)
            if struct.unpack_from('<Q',b,8)[0]!=addr: raise ValueError('Unexpected block address')
            blocks.append((addr,b))
        regions=[(a,b[:min(len(b),starts[i+1]-a)] if i+1<len(blocks) else b) for i,(a,b) in enumerate(blocks)]
        candidates=semantic(regions)
        row={'model':name,'semantic_candidates':[]}
        for p in candidates:
            row['semantic_candidates'].append({'address':hex(p),'instructions':prior.code(regions,p-0x20,0x90)})
        start=candidates[0]-0x24
        delta={'X-H2 5.30':0,'X-H2S 7.30':0,'X-T5 4.31':0x10,'X100VI 1.31':0x70}[name]
        row['direct_calls']={}
        targets=[start]
        if name=='X-H2 5.30': targets += [0x13410f0,0x2dde56c,0x2dde6a0]
        for target in targets:
            sites=calls(regions,target)
            row['direct_calls'][hex(target)]=[{'address':hex(s),'context':prior.code(regions,s-0x28,0x80)} for s in sites]
        row['vm']=[vm(regions,start,{start+0x80,start+0x1c4},cap,delta) for cap in (0xaf,0xb0)]
        row['vm_continuation']=vm(regions,start,set(),0x4030,delta,True,0x4000)
        if name=='X-H2 5.30':
            row['record_post_buffer_context']=prior.code(regions,0x2dde7f0,0x100)
            row['record_caller_post_context']=prior.code(regions,0x2e3bdc0,0x8c)
            row['post_record_call_context']=prior.code(regions,0x2e3afdc,0x180)
            row['dispatcher_literal_refs']=literal_refs(regions,0x13410f0)
            row['dispatcher_context']=prior.code(regions,0x13410f0,0x90)
        results.append(row)
        print(name,'candidates', [hex(x) for x in candidates], 'calls', {k:len(v) for k,v in row.get('direct_calls',{}).items()}, flush=True)
    after={name:digest(ROOT/filename) for name,filename,*_ in prior.MODELS}
    if before!=after: raise ValueError('DAT changed')
    (HERE/'результат.json').write_text(json.dumps({'input_sha256_before':before,'input_sha256_after':after,'models':results},ensure_ascii=False,indent=2)+'\n',encoding='utf-8')
if __name__=='__main__': main()
