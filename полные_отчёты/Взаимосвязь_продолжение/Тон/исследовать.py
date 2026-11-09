"""Исходные инструкции ARM64, синтетическая память; фотографии не читаются."""
from pathlib import Path
import hashlib, importlib.util, json, struct, sys
from capstone import Cs, CS_ARCH_ARM64, CS_MODE_LITTLE_ENDIAN
from unicorn import Uc, UC_ARCH_ARM64, UC_MODE_ARM, UC_HOOK_MEM_WRITE
from unicorn.arm64_const import UC_ARM64_REG_PC, UC_ARM64_REG_X2, UC_ARM64_REG_X19, UC_ARM64_REG_X20, UC_ARM64_REG_X21, UC_ARM64_REG_SP, UC_ARM64_REG_X30

HERE = Path(__file__).resolve().parent
ANALYSIS = HERE.parents[1]
sys.path.insert(0, str(ANALYSIS / 'инструменты'))
spec = importlib.util.spec_from_file_location('calc', ANALYSIS / 'Единый_глубокий_анализ/сопоставить_цветовые_расчёты.py')
calc = importlib.util.module_from_spec(spec); spec.loader.exec_module(calc)
tables = calc.tables
md = Cs(CS_ARCH_ARM64, CS_MODE_LITTLE_ENDIAN)
MODE_OFF = {'X-H2':0x58ac30,'X-H2S':0x5859a8,'X-T5':0x588f2c,'X100VI':0x5bfee4}
# X-H2 known entry, and a stable local instruction substring located inside it.
reference = None
result = {}
for name, (_, _, pointer) in calc.CONFIG.items():
    rel, expected, ao, bo, _, _, template, _ = tables.FILES[name]
    path = ANALYSIS.parent / rel
    raw = path.read_bytes(); before = hashlib.sha256(raw).hexdigest()
    if before != expected: raise ValueError(f'{name}: unexpected DAT hash')
    data = raw.translate(tables.base.TRANSLATION)
    a, b = tables.base.unpack_fflz(data, ao), tables.base.unpack_fflz(data, bo)
    ba, bb = struct.unpack_from('<Q',a,8)[0], struct.unpack_from('<Q',b,8)[0]
    if reference is None:
        off = 0x2f22acc - bb
        reference = b[off:off+0x120]
    # Find exact sub-sequences independent of relocated BL instructions. Require
    # consensus on inferred entry; this is a candidate, not proof of identity.
    candidates = {}
    for pos in range(0, len(reference)-16, 4):
        needle = reference[pos:pos+16]
        start = 0
        while True:
            at = b.find(needle,start)
            if at < 0: break
            entry = at-pos
            if entry >= 0 and entry % 4 == 0: candidates[entry] = candidates.get(entry,0)+1
            start = at+1
    ranked = sorted(candidates.items(), key=lambda p:p[1], reverse=True)
    if not ranked or ranked[0][1] < 4 or (len(ranked)>1 and ranked[0][1] == ranked[1][1]):
        result[name] = {'source_sha256_before':before,'status':'no unambiguous candidate','candidates':ranked[:5]}
        continue
    fn = bb+ranked[0][0]
    def find_calls(target):
        found=[]
        for i,(word,) in enumerate(struct.iter_unpack('<I',b[:len(b)//4*4])):
            if word >> 26 == 0x25:
                imm=word & 0x3ffffff
                if imm & 0x2000000: imm -= 0x4000000
                addr=bb+4*i
                if addr+4*imm == target: found.append(addr)
        return found
    callers=find_calls(fn)
    wrapper=fn+0x120
    wrapper_callers=find_calls(wrapper)
    # A short adapter ends at call+12; the following native function copies 40 u16.
    adapter_calls=[x for x in wrapper_callers if b[x+4-bb:x+12-bb] == bytes.fromhex('fd7bc1a8c0035fd6')]
    copier=adapter_calls[0]+12 if len(adapter_calls)==1 else None
    uc=Uc(UC_ARCH_ARM64,UC_MODE_ARM)
    uc.mem_map(ba,0x6000000-ba); uc.mem_write(ba,a); uc.mem_write(bb,b)
    uc.mem_map(0x27008000,0x100000); uc.mem_write(0x27008000,data[template:template+0xc6c00])
    uc.mem_write(pointer,struct.pack('<Q',0x27008000))
    uc.mem_map(0x60000000,0x40000); uc.mem_map(0x70000000,0x10000)
    src,desc,out=0x60000000,0x60020000,0x60010000
    runs=[]
    for mode in (0,19):
        uc.mem_write(src,bytes(0x1000)); calc.run(uc,bb+MODE_OFF[name],[src,mode]); code=struct.unpack('<I',uc.mem_read(src,4))[0]
        for h,s in ((8,8),(11,9),(11,8),(8,9)):
            for p in (src,desc,out): uc.mem_write(p,bytes(0x1000))
            for k,v in ((0x12c,1),(0x130,code),(0x114,h),(0x118,s)): uc.mem_write(src+k,struct.pack('<I',v))
            writes=[]
            def hook(uc,access,address,size,value,user):
                pc=uc.reg_read(UC_ARM64_REG_PC)
                writes.append({'pc':hex(pc),'offset':hex(address-out),'size':size,'value':value})
            hh=uc.hook_add(UC_HOOK_MEM_WRITE,hook,begin=out,end=out+79)
            try:
                uc.reg_write(UC_ARM64_REG_X2,out)
                calc.run(uc,fn,[src,desc,out])
                output=list(struct.unpack('<40H',uc.mem_read(out,80)))
                status='completed'
            except Exception as e:
                status=f'{type(e).__name__}: {e}'; output=None
            uc.hook_del(hh)
            copy_result=None
            if copier is not None and output is not None:
                dest=0x60030000
                uc.mem_write(dest,b'\xa5'*0x1000)
                copy_writes=[]
                def capture(uc,access,address,size,value,user):
                    copy_writes.append({'pc':hex(uc.reg_read(UC_ARM64_REG_PC)),'offset':hex(address-dest),'size':size,'value':value})
                hook_id=uc.hook_add(UC_HOOK_MEM_WRITE,capture,begin=dest,end=dest+0xff)
                calc.run(uc,copier,[out,dest])
                uc.hook_del(hook_id)
                copied=bytes(uc.mem_read(dest+0x30,80))
                copy_result={'copied_u16':list(struct.unpack('<40H',copied)),'equal':copied==bytes(uc.mem_read(out,80)),'prefix_unchanged':bytes(uc.mem_read(dest,0x30))==b'\xa5'*0x30,'suffix_unchanged':bytes(uc.mem_read(dest+0x80,0x80))==b'\xa5'*0x80,'writes':copy_writes}
                if not copy_result['equal']: raise ValueError('copier did not preserve data')
            runs.append({'mode':mode,'mode_code':code,'H':h,'S':s,'status':status,'output':output,'output_writes':writes,'context_byte_1a4':bytes(uc.mem_read(src+0x1a4,1))[0],'native_copier':copy_result})
    # Enter after prior feature checks: forced w21=0, synthetic context.
    # Stop before wrapper epilogue because the wrapper prologue was not run.
    uc.mem_write(src,bytes(0x1000)); uc.mem_write(out,b'\xa5'*0x1000)
    uc.reg_write(UC_ARM64_REG_X19,src); uc.reg_write(UC_ARM64_REG_X20,out)
    uc.reg_write(UC_ARM64_REG_X21,0); uc.reg_write(UC_ARM64_REG_SP,0x7000f000)
    control_writes=[]
    def capture_control(uc,access,address,size,value,user):
        control_writes.append({'pc':hex(uc.reg_read(UC_ARM64_REG_PC)),'offset':hex(address-out),'size':size,'value':value})
    control_hook=uc.hook_add(UC_HOOK_MEM_WRITE,capture_control,begin=out,end=out+0xff)
    uc.emu_start(callers[0]-0x18,callers[0]+0x2c,count=10000)
    uc.hook_del(control_hook)
    bypass={'start':hex(callers[0]-0x18),'stop':hex(uc.reg_read(UC_ARM64_REG_PC)),'forced_w21':0,'output':list(struct.unpack('<40H',uc.mem_read(out,80))),'context_byte_1a4':bytes(uc.mem_read(src+0x1a4,1))[0],'writes':control_writes,'suffix_unchanged':bytes(uc.mem_read(out+80,0x30))==b'\xa5'*0x30}
    assembly=copier+0x144 if copier else None
    assembly_calls=find_calls(assembly) if assembly else []
    windows={}
    for call in callers+wrapper_callers+assembly_calls:
        start=max(bb,call-0x30); end=min(bb+len(b),call+0x94)
        windows[hex(call)]=[f'{ins.address:#x} {ins.mnemonic} {ins.op_str}' for ins in md.disasm(b[start-bb:end-bb],start)]
    after=hashlib.sha256(path.read_bytes()).hexdigest()
    if before!=after: raise ValueError('DAT changed')
    result[name]={'source_sha256_before':before,'source_sha256_after':after,'block_sha256':[hashlib.sha256(a).hexdigest(),hashlib.sha256(b).hexdigest()],'entry':hex(fn),'signature_votes':ranked[0][1],'callers':[hex(c) for c in callers],'wrapper':hex(wrapper),'wrapper_callers':[hex(c) for c in wrapper_callers],'copier':hex(copier) if copier else None,'assembly':hex(assembly) if assembly else None,'assembly_callers':[hex(c) for c in assembly_calls],'bypass_control':bypass,'caller_windows':windows,'translator':hex(bb+MODE_OFF[name]),'settings_pointer':hex(pointer),'runs':runs}
(HERE/'результаты.json').write_text(json.dumps(result,ensure_ascii=False,indent=2)+'\n',encoding='utf-8')
print(json.dumps({k:{'entry':v.get('entry'),'callers':v.get('callers'),'runs':[{'H':r['H'],'S':r['S'],'mode':r['mode'],'status':r['status'],'output':r['output'],'write_pcs':sorted({w['pc'] for w in r['output_writes']})} for r in v.get('runs',[])]} for k,v in result.items()},ensure_ascii=False))
