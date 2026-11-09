"""Оригинальные AF-инструкции четырёх DAT в синтетической памяти Unicorn."""
from pathlib import Path
import hashlib, importlib.util, json, struct, sys
from capstone import Cs, CS_ARCH_ARM64, CS_MODE_ARM
from unicorn import Uc, UcError, UC_ARCH_ARM64, UC_MODE_ARM, UC_HOOK_CODE, UC_HOOK_MEM_READ, UC_HOOK_MEM_WRITE, UC_HOOK_MEM_INVALID
from unicorn import arm64_const as R

HERE = Path(__file__).resolve().parent
AN = HERE.parents[1]
ROOT = AN.parent
sys.path.insert(0, str(AN / 'инструменты'))
def load(name, path):
    spec = importlib.util.spec_from_file_location(name, path)
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod
prev = load('af_prev', AN / 'Последовательное_исследование/Этап_5/Автофокус/исследовать.py')
cs = Cs(CS_ARCH_ARM64, CS_MODE_ARM)
def hx(n): return hex(n)
def unpack(fmt, data): return struct.unpack(fmt, bytes(data))[0]
def main():
    out = {}
    for name, c in prev.CONFIG.items():
        path, expected, offsets, handler, wrapper, lookup, norm, classify, ptr, u16, slot, threshold, table, values = c
        source = ROOT / path
        raw = source.read_bytes()
        before = hashlib.sha256(raw).hexdigest()
        if before != expected: raise ValueError(name + ': неверный SHA256')
        decoded = raw.translate(prev.base.TRANSLATION)
        blocks = []
        for off in offsets:
            b = prev.base.unpack_fflz(decoded, off)
            blocks.append((struct.unpack_from('<Q', b, 8)[0], b, off))
        def original(addr, length):
            for base, b, _ in blocks:
                if base <= addr and addr + length <= base + len(b): return b[addr-base:addr-base+length]
            raise ValueError(hex(addr))
        def ins(addr, length):
            return [{'pc':hx(i.address),'bytes':bytes(i.bytes).hex(),'op':i.mnemonic,'args':i.op_str} for i in cs.disasm(original(addr,length),addr)]
        boundary = handler + 0x58
        target = int(ins(boundary,4)[0]['args'].lstrip('#'),16)
        inner = int(ins(target+8,4)[0]['args'].lstrip('#'),16)
        runs=[]
        for label, byte, bad in [('zero',0,False),('one',1,False),('high_bit',128,False),('unmapped_flag',0,False),('unmapped',0,True)]:
            u=Uc(UC_ARCH_ARM64,UC_MODE_ARM)
            u.mem_map(0x1000,0x6000000-0x1000)
            for base,b,_ in blocks: u.mem_write(base,b)
            u.mem_map(0x70000000,0x100000)
            u.mem_map(0x71000000,0x800000)
            u.reg_write(R.UC_ARM64_REG_SP,0x700ff000)
            u.reg_write(R.UC_ARM64_REG_X0,0x70002000)
            u.mem_write(0x70002000,struct.pack('<QQQ',0x70001000,0x70010000,0x70030000))
            u.mem_write(0x70001000,struct.pack('<I',0x89abcdef))
            u.mem_write(0x70001018,struct.pack('<I',2))
            u.mem_write(0x70001020,struct.pack('<I',4))
            u.mem_write(0x70001040,struct.pack('<I',0x10203040))
            u.mem_write(slot,struct.pack('<Q',0x90000000 if bad else 0x71000000))
            u.mem_write(threshold,struct.pack('<I',16))
            u.mem_write(0x71000000+table+2*31+4,b'\x03')
            u.mem_write(0x71000000+values+6,struct.pack('<H',0x1234))
            u.mem_write(0x7101000d,bytes([byte]))
            if label == 'unmapped_flag': u.mem_unmap(0x71010000,0x1000)
            result={'case':label,'byte_at_base_plus_1000d':None if label=='unmapped_flag' else byte,'events':[],'data_reads':[],'data_writes':[],'continuation':[]}
            state={'after':False,'calls':0}
            def code(uc,pc,size,user):
                if pc==boundary: result['events'].append({'kind':'boundary','pc':hx(pc),'w0':hx(uc.reg_read(R.UC_ARM64_REG_W0))})
                if pc==target: result['events'].append({'kind':'accessor','pc':hx(pc),'w0':hx(uc.reg_read(R.UC_ARM64_REG_W0))})
                if pc==inner and uc.reg_read(R.UC_ARM64_REG_W0)==0x1000d: result['events'].append({'kind':'byte_reader','pc':hx(pc),'w0':'0x1000d'})
                if pc==boundary+4:
                    state['after']=True
                    result['events'].append({'kind':'return','pc':hx(pc),'w0':hx(uc.reg_read(R.UC_ARM64_REG_W0))})
                if state['after']:
                    op=next(cs.disasm(bytes(uc.mem_read(pc,4)),pc))
                    result['continuation'].append({'pc':hx(pc),'instruction':op.mnemonic+' '+op.op_str})
                    if op.mnemonic=='bl':
                        state['calls'] += 1
                        result['events'].append({'kind':'call' if state['calls']==1 else 'stop_before_second_call','pc':hx(pc),'instruction':op.mnemonic+' '+op.op_str,'x0':hx(uc.reg_read(R.UC_ARM64_REG_X0)),'x1':hx(uc.reg_read(R.UC_ARM64_REG_X1)),'x2':hx(uc.reg_read(R.UC_ARM64_REG_X2))})
                        if state['calls']==2: uc.emu_stop()
            def memory(uc,access,address,size,value,user):
                pc=uc.reg_read(R.UC_ARM64_REG_PC)
                if access==16:
                    if address==0x7101000d: result['data_reads'].append({'pc':hx(pc),'address':hx(address),'size':size,'bytes':bytes(uc.mem_read(address,size)).hex()})
                elif state['after'] and 0x70010000 <= address < 0x70010010:
                    result['data_writes'].append({'pc':hx(pc),'address':hx(address),'size':size,'value':hx(value)})
            def invalid(uc,access,address,size,value,user):
                result['invalid']={'pc':hx(uc.reg_read(R.UC_ARM64_REG_PC)),'address':hx(address),'size':size,'access':access}
                return False
            u.hook_add(UC_HOOK_CODE,code)
            u.hook_add(UC_HOOK_MEM_READ | UC_HOOK_MEM_WRITE,memory)
            u.hook_add(UC_HOOK_MEM_INVALID,invalid)
            try: u.emu_start(handler,0,count=6000)
            except UcError as e: result['error']=str(e)
            runs.append(result)
        after=hashlib.sha256(source.read_bytes()).hexdigest()
        if before != after: raise ValueError(name + ': DAT изменился')
        out[name]={'source':path,'sha256_before':before,'sha256_after':after,'blocks':[{'base':hx(a),'dat_offset':hx(off),'length':len(b),'sha256':hashlib.sha256(b).hexdigest()} for a,b,off in blocks], 'handler':hx(handler),'boundary':hx(boundary),'accessor':hx(target),'byte_reader':hx(inner),'slot':hx(slot),'handler_instructions':ins(handler,0x180),'accessor_instructions':ins(target,0x14),'reader_instructions':ins(inner,0x28),'runs':runs}
        print(name, [(r['case'],r['events'][-1] if r['events'] else r.get('invalid')) for r in runs])
    (HERE/'результаты.json').write_text(json.dumps(out,ensure_ascii=False,indent=2),encoding='utf-8')
if __name__=='__main__': main()
