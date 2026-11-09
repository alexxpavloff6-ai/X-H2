"""Изолированная ARM64 VM и сравнительный поиск; исходные DAT только читаются."""
from pathlib import Path
import sys, importlib.util, json, struct, hashlib
sys.dont_write_bytecode = True
HERE = Path(__file__).resolve().parent
ROOT = HERE.parents[2]
AN = ROOT / 'Анализ_прошивки'
spec = importlib.util.spec_from_file_location('record_prior', AN / 'Взаимосвязь_продолжение/Запись/исследовать.py')
p = importlib.util.module_from_spec(spec); spec.loader.exec_module(p)
from unicorn import Uc, UC_ARCH_ARM64, UC_MODE_ARM, UC_HOOK_CODE, UcError
from unicorn.arm64_const import *

# dispatcher, caller to serializer, serializer, offsets for object fields
MODELS = {
 'X-H2 5.30': (0x13410f0,0x1341168,0x134cea8,0),
 'X-H2S 7.30': (0x165ecec,0x165ed64,0x166aa88,0),
 'X-T5 4.31': (0x133e170,0x133e1e8,0x1349e78,0x10),
 'X100VI 1.31': (0x1426770,0x14267e8,0x1434014,0x70),
}

def adrp_add(regions, target):
    # ADRP + ADD immediate в следующих 8 инструкциях, регистр не отслеживается
    # через промежуточные записи: результат только поисковый кандидат.
    out=[]
    for base,data in regions:
        w=p.np.frombuffer(data[:len(data)//4*4],dtype='<u4')
        for idx in p.np.nonzero((w & 0x9f000000)==0x90000000)[0]:
            v=int(w[idx]); pc=base+int(idx)*4
            imm=((v>>29)&3)|(((v>>5)&0x7ffff)<<2)
            if imm & (1<<20): imm-=1<<21
            if ((pc & ~4095)+(imm<<12)) != (target & ~4095): continue
            reg=v&31
            for j in range(1,9):
                if idx+j>=len(w): break
                a=int(w[idx+j])
                if a&0xffc00000==0x91000000 and (a>>5)&31==reg and (a>>10)&0xfff==target&0xfff:
                    out.append({'adrp':hex(pc),'add':hex(pc+j*4),'context':p.prior.code(regions,pc,4*(j+1))})
    return out

def patterns(regions):
    # В X-H2 это ldr x0,[x25,#8]; bl; str w0,[x25,#0x18].
    # BL произволен, совпадающие регистры/смещения зафиксированы.
    found=[]
    for base,data in regions:
        at=0
        while True:
            at=data.find(bytes.fromhex('200740f9'),at)
            if at<0: break
            if at%4==0 and at+12<=len(data) and data[at+8:at+12]==bytes.fromhex('201b00b9') and int.from_bytes(data[at+4:at+8],'little')&0xfc000000==0x94000000:
                pc=base+at
                found.append({'address':hex(pc),'context':p.prior.code(regions,pc-0x20,0x48)})
            at+=1
    return found

def indirect_search(regions, target, record_site):
    """Ограниченные представления адреса и пары полей: кандидаты, не граф вызовов."""
    np=p.np
    result={'direct_b':[], 'adr':[], 'relative32_byte':[], 'relative32_word':[],
            'region_base_relative32':[], 'paired_loads_near_record':[], 'paired_load_count':0}
    pairs=[]
    for base,data in regions:
        w=np.frombuffer(data[:len(data)//4*4],dtype='<u4')
        indexes=np.arange(len(w),dtype=np.int64); pc=base+4*indexes
        signed=w.astype(np.int64); signed[signed>=0x80000000]-=0x100000000
        for key, mask in [('relative32_byte',pc+signed==target),('relative32_word',pc+4*signed==target),
                          ('region_base_relative32',signed==target-base)]:
            for idx in np.flatnonzero(mask):
                result[key].append({'address':hex(int(pc[idx])),'word':hex(int(w[idx]))})
        ids=np.flatnonzero((w & 0xfc000000)==0x14000000)
        vals=w[ids].astype(np.int64)&0x3ffffff; vals[vals&0x2000000!=0]-=0x4000000
        result['direct_b'].extend(hex(int(pc[i])) for i in ids[pc[ids]+vals*4==target])
        ids=np.flatnonzero((w & 0x9f000000)==0x10000000)
        vals=(((w[ids]>>29)&3)|(((w[ids]>>5)&0x7ffff)<<2)).astype(np.int64)
        vals[vals&(1<<20)!=0]-=1<<21
        result['adr'].extend(hex(int(pc[i])) for i in ids[pc[ids]+vals==target])
        # ldr xT,[xN,#8] followed within 16 instructions by ldr wM,[xN,#0x18].
        ids=np.flatnonzero((w & 0xfffffc00)==0xf9400400)
        for idx in ids:
            reg=(int(w[idx])>>5)&31
            end=min(len(w),idx+17)
            for j in range(int(idx)+1,int(end)):
                v=int(w[j])
                if v&0xfffffc00==0xb9401800 and (v>>5)&31==reg:
                    loc=int(pc[idx]); pairs.append((abs(loc-record_site),loc,int(pc[j]),reg))
    result['paired_load_count']=len(pairs)
    for _,first,second,reg in sorted(pairs)[:40]:
        region=next((a,b) for a,b in regions if a<=first and second+20<=a+len(b))
        left=max(region[0],first-0x10)
        result['paired_loads_near_record'].append({'first':hex(first),'second':hex(second),
          'base_register':reg,'context':p.prior.code(regions,left,second+20-left)})
    return result

def pair_transfer_vm(regions, start, control=False):
    # Отдельный фрагмент: x21 и x19 искусственные; происхождение объектов не доказано.
    u=Uc(UC_ARCH_ARM64,UC_MODE_ARM); u.mem_map(0x40000,0x5fc0000)
    for a,b in regions: u.mem_write(a,b)
    u.mem_map(0x70000000,0x10000)
    one,two,out=0x70001000,0x70002000,0x70003000
    u.mem_write(one+8,struct.pack('<Q',0x71111000))
    u.mem_write(one+0x18,struct.pack('<I',0x13579bdf if not control else 0))
    u.mem_write(two+8,struct.pack('<Q',0x72222000))
    u.mem_write(two+0x18,struct.pack('<I',0x2468ace0))
    u.mem_write(out,bytes([0xa5])*0x40)
    u.reg_write(UC_ARM64_REG_X21,one); u.reg_write(UC_ARM64_REG_X19,two)
    u.reg_write(UC_ARM64_REG_X20,out); u.reg_write(UC_ARM64_REG_SP,0x7000f000)
    error=None
    try: u.emu_start(start,start+0x20,count=8)
    except UcError as e: error=str(e)
    b=bytes(u.mem_read(out,0x40))
    return {'control_zero_first_size':control,'start':hex(start),'stop_pc':hex(u.reg_read(UC_ARM64_REG_PC)),
      'error':error,'input_objects':{'x21':hex(one),'x19':hex(two),'x20':hex(out),
      'first_pointer':'0x71111000','first_size':hex(0 if control else 0x13579bdf),
      'second_pointer':'0x72222000','second_size':'0x2468ace0'},
      'destination_after_hex':b.hex(),'destination_fields':{'pointer_8':hex(struct.unpack_from('<Q',b,8)[0]),
      'word_10':hex(struct.unpack_from('<I',b,0x10)[0]),'pointer_18':hex(struct.unpack_from('<Q',b,0x18)[0]),
      'word_20':hex(struct.unpack_from('<I',b,0x20)[0])}}

def sum_consumer_vm(regions, start, exit_nonzero, exit_zero, offset, control=False):
    # Изолированный цикл после условных вызовов, не ручное продолжение предыдущей VM.
    u=Uc(UC_ARCH_ARM64,UC_MODE_ARM); u.mem_map(0x40000,0x5fc0000)
    for a,b in regions: u.mem_write(a,b)
    base=0x70010000
    u.mem_map(base,0x10000)
    first=0 if control else 0x30
    u.mem_write(base+offset+0x10,struct.pack('<I',first))
    u.mem_write(base+offset+0x20,struct.pack('<I',0x20))
    u.mem_write(base+offset+0x30,struct.pack('<I',0))
    u.reg_write(UC_ARM64_REG_X23,base);u.reg_write(UC_ARM64_REG_X19,4)
    u.reg_write(UC_ARM64_REG_X22,7);u.reg_write(UC_ARM64_REG_SP,base+0xf000)
    stops=[]
    def hook(uc,addr,size,user):
        if addr in (exit_nonzero,exit_zero):
            stops.append(hex(addr));uc.emu_stop()
    u.hook_add(UC_HOOK_CODE,hook)
    error=None
    try: u.emu_start(start,0,count=100)
    except UcError as e: error=str(e)
    return {'first_size':hex(first),'second_size':'0x20','initial_sum':'0x7','index':4,
       'object':hex(base),'descriptor_offset':hex(offset),'stop_pc':hex(u.reg_read(UC_ARM64_REG_PC)),
       'sum_w22':hex(u.reg_read(UC_ARM64_REG_X22)&0xffffffff),'stops':stops,'error':error}

def vm(regions, disp, site, serializer, delta, mode, subtype, capacity, trace):
    u=Uc(UC_ARCH_ARM64,UC_MODE_ARM); u.mem_map(0x40000,0x5fc0000)
    for a,b in regions: u.mem_write(a,b)
    u.mem_map(0x70000000,0x60000)
    obj=0x70010000; dst=0x70050000; src=bytes((0x21+7*i)&255 for i in range(48))
    initial=bytes([0xa5])*0x5000
    u.mem_write(dst,initial); u.mem_write(0x70002000,src)
    u.mem_write(obj,struct.pack('<IB',mode,subtype))
    for off,value,fmt in [(0x13270+delta,0x70002000,'Q'),(0x13278+delta,0x4000 if capacity==0x4030 else 0x80,'I'),(0x13280+delta,0x70003000,'Q'),(0x13288+delta,0,'I'),(0x13290+delta,0x70002030,'Q')]:
        u.mem_write(obj+off,struct.pack('<'+fmt,value))
    u.mem_write(0x70030000,struct.pack('<I',capacity))
    u.reg_write(UC_ARM64_REG_X0,dst); u.reg_write(UC_ARM64_REG_X1,0x70030000); u.reg_write(UC_ARM64_REG_X2,obj)
    u.reg_write(UC_ARM64_REG_SP,0x7004f000); u.reg_write(UC_ARM64_REG_X30,0x70040000)
    seen=[]; calls=[]; inner_calls=[]; error=None
    def hook(uc,addr,size,user):
        if mode==4 and not (disp <= addr < disp+0x90) and len(inner_calls)<200:
            word=int.from_bytes(uc.mem_read(addr,4),'little')
            if word&0xfc000000==0x94000000:
                imm=word&0x3ffffff
                if imm&0x2000000: imm-=0x4000000
                inner_calls.append({'pc':hex(addr),'target':hex(addr+imm*4),'x0':hex(uc.reg_read(UC_ARM64_REG_X0)),'x1':hex(uc.reg_read(UC_ARM64_REG_X1)),'x2':hex(uc.reg_read(UC_ARM64_REG_X2))})
        if disp <= addr < disp+0x90:
            seen.append(hex(addr))
            word=int.from_bytes(uc.mem_read(addr,4),'little')
            if word&0xfc000000==0x94000000:
                imm=word&0x3ffffff
                if imm&0x2000000: imm-=0x4000000
                calls.append({'pc':hex(addr),'target':hex(addr+imm*4),'x0':hex(uc.reg_read(UC_ARM64_REG_X0)),'x1':hex(uc.reg_read(UC_ARM64_REG_X1)),'x2':hex(uc.reg_read(UC_ARM64_REG_X2))})
                if mode==0: uc.emu_stop(); return
        if addr==0x70040000 or (capacity==0xb0 and mode==1 and addr==serializer+0x80): uc.emu_stop()
    u.hook_add(UC_HOOK_CODE,hook)
    try: u.emu_start(disp,0,count=1000000)
    except UcError as e: error=str(e)
    out=bytes(u.mem_read(dst,len(initial)))
    return {'mode':mode,'subtype':subtype,'capacity':hex(capacity),'reserve':hex(0x4000 if capacity==0x4030 else 0x80),'dispatcher_pcs':seen,'dispatcher_calls':calls,'inner_calls_first_200':inner_calls,'stop_pc':hex(u.reg_read(UC_ARM64_REG_PC)),'x0':hex(u.reg_read(UC_ARM64_REG_X0)),'error':error,'returned':u.reg_read(UC_ARM64_REG_PC)==0x70040000,'capacity_after':hex(int.from_bytes(u.mem_read(0x70030000,4),'little')),'output_unchanged':out==initial,'first_48_match':out[:48]==src,'output_sha256':hashlib.sha256(out).hexdigest()}

def main():
    before={name:p.digest(ROOT/filename) for name,filename,*_ in p.prior.MODELS}; rows=[]
    for name,filename,expected,offsets,starts in p.prior.MODELS:
        if before[name]!=expected: raise ValueError('DAT SHA256 mismatch '+name)
        raw=(ROOT/filename).read_bytes().translate(p.prior.base.TRANSLATION); blocks=[]
        for off,start in zip(offsets,starts):
            b=p.prior.base.unpack_fflz(raw,off)
            if struct.unpack_from('<Q',b,8)[0]!=start: raise ValueError('block address')
            blocks.append((start,b))
        regions=[(a,b[:min(len(b),starts[i+1]-a)] if i+1<len(blocks) else b) for i,(a,b) in enumerate(blocks)]
        disp,site,ser,delta=MODELS[name]
        row={'model':name,'dat':filename,'regions':[{'start':hex(a),'end_exclusive':hex(a+len(b)),'sha256':hashlib.sha256(b).hexdigest()} for a,b in regions], 'dispatcher':hex(disp),'dispatcher_instructions':p.prior.code(regions,disp,0x90),'serializer':hex(ser),'direct_calls_dispatcher':[hex(x) for x in p.calls(regions,disp)],'aligned_literals_dispatcher':p.literal_refs(regions,disp),'adrp_add_candidates_dispatcher':adrp_add(regions,disp),'buffer_return_pattern':patterns(regions)}
        record={'X-H2 5.30':0x2ddea3c,'X-H2S 7.30':0x30f607c,'X-T5 4.31':0x2d1c01c,'X100VI 1.31':0x2fe6760}[name]
        row['indirect_and_buffer_search']=indirect_search(regions,disp,record)
        transfer={'X-H2 5.30':0x2ddecf8,'X-H2S 7.30':0x30f61e4,'X-T5 4.31':0x2d1c2d8,'X100VI 1.31':0x2fe6a20}[name]
        row['pair_transfer_context']=p.prior.code(regions,transfer-0xc0,0x160)
        transfer_function=transfer-0x78
        transfer_callers=p.calls(regions,transfer_function)
        row['pair_transfer_function']=hex(transfer_function)
        row['pair_transfer_direct_callers']=[{'site':hex(x),'context':p.prior.code(regions,x-0x30,0x60)} for x in transfer_callers]
        post={'X-H2 5.30':0x2ddef64,'X-H2S 7.30':0x30f6450,'X-T5 4.31':0x2d1c544,'X100VI 1.31':0x2fe6c8c}[name]
        row['pair_transfer_caller_continuation']=p.prior.code(regions,post,0x100)
        row['pair_transfer_vm']=[pair_transfer_vm(regions,transfer,control) for control in (False,True)]
        loop={'X-H2 5.30':(0x2ddefb0,0x2ddefdc,0x2ddf3ac,0x68e0),
              'X-H2S 7.30':(0x30f649c,0x30f64c8,0x30f6894,0x6888),
              'X-T5 4.31':(0x2d1c590,0x2d1c5bc,0x2d1c988,0x6a60),
              'X100VI 1.31':(0x2fe6ce0,0x2fe6d0c,0x2fe70e8,0x7008)}[name]
        row['size_consumer_vm']=[sum_consumer_vm(regions,*loop,control) for control in (False,True)]
        second={'X-H2 5.30':0x1353a84,'X-H2S 7.30':0x1671664,'X-T5 4.31':0x1350a54,'X100VI 1.31':0x143bcac}[name]
        row['second_serializer_instructions']=p.prior.code(regions,second,0x180)
        row['experiments']=[vm(regions,disp,site,ser,delta,m,s,c,False) for m,s,c in [(1,0,0xaf),(1,0,0xb0),(1,0,0x4030),(4,0,0xaf),(4,0,0xb0),(4,0,0x4030),(0,1,0x4030),(0,2,0x4030),(0,4,0x4030),(0,3,0x4030),(2,0,0x4030),(0xffffffff,0,0x4030)]]
        rows.append(row); print(name,[(x['mode'],x['subtype'],x['stop_pc'],x['error']) for x in row['experiments']],flush=True)
    after={name:p.digest(ROOT/filename) for name,filename,*_ in p.prior.MODELS}
    if before!=after: raise ValueError('DAT changed')
    (HERE/'результат.json').write_text(json.dumps({'input_sha256_before':before,'input_sha256_after':after,'models':rows},ensure_ascii=False,indent=2)+'\n',encoding='utf-8')
if __name__=='__main__': main()
