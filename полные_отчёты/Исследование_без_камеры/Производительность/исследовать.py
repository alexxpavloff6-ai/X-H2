"""Локальное исследование словарей и диспетчера; только чтение DAT, камера не используется."""
from pathlib import Path
import hashlib, importlib.util, json, re, struct, sys
HERE = Path(__file__).resolve().parent
AN = HERE.parents[1]
ROOT = AN.parent
sys.path.insert(0, str(AN / 'инструменты'))
def load(name, path):
    spec = importlib.util.spec_from_file_location(name, path)
    module = importlib.util.module_from_spec(spec); spec.loader.exec_module(module)
    return module
base = load('decoder', AN / 'анализ_файла.py')
from capstone import Cs, CS_ARCH_ARM64, CS_MODE_ARM
from unicorn import Uc, UcError, UC_ARCH_ARM64, UC_MODE_ARM, UC_HOOK_CODE, UC_HOOK_MEM_READ, UC_HOOK_MEM_WRITE
from unicorn import arm64_const as R

# source, digest, compressed block offsets, dispatcher, getter call, converter call, consumer call
CONFIG = {
 'X-H2 5.30': ('FIRMWARE/ver 5.30/FWUP0028.DAT','be47168cb075ef726e67cb4bb08175a896047a3b0de2bcb6e65333b22cfcb203',(0x300274,0x840274),0x2bd0b2c,0x2bd0bb4,0x2bd0b78,0x2bd0b88),
 'X-H2S 7.30': ('Firmware на прочиеFuji/FWUP0027.DAT','87c566c1ff6343e4c7463a4ef968183f41d1f24cc63d610433d3a387b13f731b',(0x300274,0x840274),0x2eea798,0x2eea820,0x2eea7e4,0x2eea7f4),
 'X-T5 4.31': ('Firmware на прочиеFuji/FWUP0030.DAT','790d6deecf26766188b0e506e40645e6b816addfeba39a52334349405421724e',(0x300274,0x820274),0x2b11c6c,0x2b11cf4,0x2b11cb8,0x2b11cc8),
 'X100VI 1.31': ('Firmware на прочиеFuji/FPUPDATE.DAT','0d48d2ae26ac7ebab9b0e4cac56324807ec1ea8ae30df06b0b9e79066dc0a14a',(0x9c02bc,0x10e02bc),0x2dcc650,0x2dcc6d8,0x2dcc69c,0x2dcc6ac),
}
TABLES = {'X-H2 5.30':(0x1bd5ab8,1466,0x12e67ac),
          'X-H2S 7.30':(0x1ef1aa8,1466,0x1604da0),
          'X-T5 4.31':(0x1bb1a30,1426,0x12e48b0),
          'X100VI 1.31':(0x1c60a50,1530,0x13c9930)}
# Candidate byte of indexed setting bank, actual getter-read byte under this synthetic state,
# consumer wrapper, inner consumer, record writer, diagnostic flag, candidate setter context.
CONTINUED = {
 'X-H2 5.30': (0x2628df8,0x2628df8,0x2c4fe6c,0x2c4fd98,0x12e863c,0x267ebed,0x1205048),
 'X-H2S 7.30': (0x2944df0,0x2944df0,0x2f68024,0x2f67f50,0x1606b6c,0x299abe5,0x15239ec),
 'X-T5 4.31': (0x257cc90,0x2586283,0x2b915dc,0x2b91508,0x12e6748,0x25bb495,0x1206cfc),
 'X100VI 1.31': (0x278d721,0x279e784,0x2e503d4,0x2e50300,0x13cb4dc,0x27f601d,0x12e5b04),
}
cs=Cs(CS_ARCH_ARM64,CS_MODE_ARM)
def sha(data): return hashlib.sha256(data).hexdigest()
def addr(x): return hex(x)
def instructions(blocks, pc, length):
    for a,b in reversed(blocks):
        if a <= pc and pc+length <= a+len(b):
            return [{'pc':addr(i.address),'bytes':i.bytes.hex(),'asm':i.mnemonic+' '+i.op_str} for i in cs.disasm(b[pc-a:pc-a+length],pc)]
    raise ValueError(hex(pc))
def direct_calls(blocks,target):
    result=[]
    for a,b in blocks:
        for pos in range(0,len(b)-3,4):
            w=struct.unpack_from('<I',b,pos)[0]
            if w>>26 != 0b100101: continue
            off=w&0x3ffffff
            if off & 0x2000000: off-=0x4000000
            if a+pos+4*off==target: result.append(a+pos)
    return sorted(set(result))
def run(blocks, start, getter, converter, consumer, event, substitute):
    u=Uc(UC_ARCH_ARM64,UC_MODE_ARM)
    u.mem_map(0x1000,0x6000000-0x1000)
    for a,b in blocks: u.mem_write(a,b)
    u.mem_map(0x70000000,0x10000)
    u.reg_write(R.UC_ARM64_REG_SP,0x7000f000)
    u.reg_write(R.UC_ARM64_REG_X0,event)
    steps=[]; calls=[]; reached=False
    def hook(uc,pc,size,unused):
        nonlocal reached
        steps.append(addr(pc))
        if pc in (getter,converter,converter+4,consumer):
            args=[uc.reg_read(getattr(R,'UC_ARM64_REG_X'+str(i))) & 0xffffffff for i in range(4)]
            if pc==consumer:
                calls.append({'at':addr(pc),'kind':'stopped_before_consumer','w0_w3':args});reached=True;uc.emu_stop();return
            if pc==getter:
                calls.append({'at':addr(pc),'kind':'substituted_getter','w0_w3':args,'synthetic_return':substitute})
                uc.reg_write(R.UC_ARM64_REG_X0,substitute)
                uc.reg_write(R.UC_ARM64_REG_PC,pc+4)
            elif pc==converter:
                calls.append({'at':addr(pc),'kind':'original_converter_call','w0_w3':args})
            else:
                calls.append({'at':addr(pc),'kind':'original_converter_return','w0':args[0]})
    u.hook_add(UC_HOOK_CODE,hook)
    u.emu_start(start,0,count=200)
    if not reached: raise RuntimeError('consumer boundary not reached')
    return {'synthetic_input_w0':event,'getter_substitution':substitute,'calls':calls,'executed_pc':steps}
def continuous(blocks, start, info, event, initial):
    candidate, getter_cell, wrapper, consumer, writer, flag, setter_context = info
    u=Uc(UC_ARCH_ARM64,UC_MODE_ARM)
    u.mem_map(0x1000,0x6000000-0x1000)
    for a,b in blocks: u.mem_write(a,b)
    u.mem_map(0x70000000,0x10000)
    u.reg_write(R.UC_ARM64_REG_SP,0x7000f000)
    u.reg_write(R.UC_ARM64_REG_X30,0x70000000)
    u.reg_write(R.UC_ARM64_REG_X0,event)
    u.mem_write(flag,b'\x00')
    for p in {candidate,getter_cell}: u.mem_write(p,bytes([initial]))
    pcs=[]; writes=[]; reads=[]
    def code(uc,pc,size,unused): pcs.append(addr(pc))
    def write_hook(uc,access,p,size,value,unused):
        if not 0x70000000 <= p < 0x70010000:
            writes.append({'pc':addr(uc.reg_read(R.UC_ARM64_REG_PC)),'address':addr(p),'size':size,'value':value})
    def read_hook(uc,access,p,size,value,unused):
        if any(p <= cell < p+size for cell in {candidate,getter_cell}):
            reads.append({'pc':addr(uc.reg_read(R.UC_ARM64_REG_PC)),'address':addr(p),'size':size})
    u.hook_add(UC_HOOK_CODE,code)
    u.hook_add(UC_HOOK_MEM_WRITE,write_hook)
    u.hook_add(UC_HOOK_MEM_READ,read_hook)
    error=None
    try: u.emu_start(start,0x70000000,count=5000)
    except UcError as ex: error=str(ex)
    pc=u.reg_read(R.UC_ARM64_REG_PC)
    return {'input_w0':event,'synthetic_initial_byte':initial,'synthetic_flag_zero':addr(flag),
            'candidate_cell':addr(candidate),'getter_read_cell':addr(getter_cell),
            'candidate_after':u.mem_read(candidate,1)[0],'getter_cell_after':u.mem_read(getter_cell,1)[0],
            'reads_of_monitored_bytes':reads,'non_stack_writes':writes,'executed_pc':pcs,
            'stop_pc':addr(pc),'returned_to_synthetic_lr':pc==0x70000000,'error':error}
def main():
    result={'method':'Two FFLZ blocks per DAT; little-endian pointer then u64 dictionary value. Only aligned direct BL scan. Boundary runs substitute default getter; continuous runs execute all code without call substitutions, using explicitly initialized synthetic RAM and return sentinel.', 'models':{}}
    for name,c in CONFIG.items():
        path,expected,offsets,start,getter,converter,consumer=c
        source=ROOT/path; raw=source.read_bytes(); before=sha(raw)
        if before!=expected: raise ValueError(name+' unexpected DAT SHA-256: '+before)
        decoded=raw.translate(base.TRANSLATION); blocks=[]; block_info=[]
        for off in offsets:
            b=base.unpack_fflz(decoded,off); a=struct.unpack_from('<Q',b,8)[0]
            blocks.append((a,b));block_info.append({'dat_offset':addr(off),'virtual_base':addr(a),'length':len(b),'sha256':sha(b)})
        # X100VI images overlap: map the later block last, as in the existing decoders.
        dictionary=[]; strings=[]
        for a,b in blocks:
            for m in re.finditer(rb'(?:UI_[A-Z0-9_]*PERFORMANCE[A-Z0-9_]*|BKUP_PERFORMANCE[A-Z0-9_]*)\x00',b):
                string=m.group()[:-1].decode('ascii'); pointer=a+m.start(); refs=[]
                for aa,bb in blocks:
                    pattern=struct.pack('<Q',pointer); p=0
                    while True:
                        p=bb.find(pattern,p)
                        if p<0: break
                        refs.append((aa,p));p+=1
                strings.append({'name':string,'string_address':addr(pointer),'block_offset':addr(m.start()),'pointer_references':[addr(aa+p) for aa,p in refs]})
                for aa,p in refs:
                    bb=next(x for q,x in blocks if q==aa)
                    if p%8==0 and p+16<=len(bb):
                        dictionary.append({'name':string,'record':addr(aa+p),'bytes':bb[p:p+16].hex(),'value_u64':struct.unpack_from('<Q',bb,p+8)[0]})
        callers=direct_calls(blocks,start)
        runs=[run(blocks,start,getter,converter,consumer,event,sub) for event,sub in [(0x201a,3),(0x201b,3),(0x201c,3),(0x201d,3),(0,3),(0,7)]]
        continuation=CONTINUED[name]
        continuous_runs=[continuous(blocks,start,continuation,event,value) for event,value in [(0x201a,1),(0x201b,1),(0x201c,1),(0x201d,1),(0,0),(0,4)]]
        after=sha(source.read_bytes())
        if before!=after: raise RuntimeError('DAT changed: '+name)
        table_base,setting,inner=TABLES[name]
        def read_at(p,n):
            for a,b in reversed(blocks):
                if a<=p and p+n<=a+len(b): return b[p-a:p-a+n]
            raise ValueError(hex(p))
        slot=table_base+8*setting
        table=struct.unpack('<Q',read_at(slot,8))[0]
        table_bytes=read_at(table,96)
        table_rows=[list(struct.unpack_from('<4I',table_bytes,j)) for j in range(0,96,16)]
        candidate,getter_cell,wrapper,consumer_inner,writer,flag,setter_context=continuation
        result['models'][name]={'source':path,'sha256_before':before,'sha256_after':after,'blocks':block_info,'strings':strings,'dictionary_records':dictionary,'dispatcher':addr(start),'dispatcher_instructions':instructions(blocks,start,0xb0),'converter_instructions':instructions(blocks,inner,0x140),'conversion_table':{'index_slot':addr(slot),'table':addr(table),'bytes':table_bytes.hex(),'rows_u32':table_rows},'callers':[{'bl':addr(p),'context':instructions(blocks,p-8,16)} for p in callers], 'runs':runs,
            'continuation':{'candidate_setting_byte':addr(candidate),'getter_byte_in_synthetic_state':addr(getter_cell),'diagnostic_flag':addr(flag),'wrapper_instructions':instructions(blocks,wrapper,0x18),'consumer_instructions':instructions(blocks,consumer_inner,0xd4),'writer_instructions':instructions(blocks,writer,0xa8),'candidate_setter_context':instructions(blocks,setter_context,0x70),'runs':continuous_runs}}
    (HERE/'результаты.json').write_text(json.dumps(result,ensure_ascii=False,indent=2)+'\n',encoding='utf-8')
    print('Готово:', ', '.join(result['models']))
if __name__=='__main__': main()
