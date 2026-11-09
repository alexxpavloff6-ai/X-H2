"""Изолированная трасса после второй AF-границы; исходные DAT только читаются."""
from pathlib import Path
import hashlib, importlib.util, json, struct, sys

HERE = Path(__file__).resolve().parent
AN = HERE.parents[2]
ROOT = AN.parent
sys.path.insert(0, str(AN / 'инструменты'))
def load(name, path):
    spec = importlib.util.spec_from_file_location(name, path)
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod
base = load('base', AN / 'анализ_файла.py')
dist = load('dist', AN / 'Распределение_систем_2026-11-01/исследовать_распределение.py')
from unicorn import Uc, UcError, UC_ARCH_ARM64, UC_MODE_ARM, UC_HOOK_CODE, UC_HOOK_MEM_READ, UC_HOOK_MEM_INVALID
from unicorn import arm64_const as R

# handler, wrapper, second boundary, normalization, classification, pointer accessor,
# 16-bit accessor, global base slot, classification threshold, logical offsets
CONFIG = {
 'X-H2 5.30': ('FIRMWARE/ver 5.30/FWUP0028.DAT','be47168cb075ef726e67cb4bb08175a896047a3b0de2bcb6e65333b22cfcb203',(0x300274,0x840274),0x314530c,0x313f0d4,0x1542080,0x1541f08,0x1541ed0,0x149b1e4,0x149b0e0,0x20c1458,0x1c69684,0x734600,0x722530),
 'X-H2S 7.30': ('Firmware на прочиеFuji/FWUP0027.DAT','87c566c1ff6343e4c7463a4ef968183f41d1f24cc63d610433d3a387b13f731b',(0x300274,0x840274),0x34573e0,0x34512fc,0x18619f4,0x186187c,0x1861844,0x17bad78,0x17bac74,0x23dbc30,0x1f85124,0x734600,0x722530),
 'X-T5 4.31': ('Firmware на прочиеFuji/FWUP0030.DAT','790d6deecf26766188b0e506e40645e6b816addfeba39a52334349405421724e',(0x300274,0x820274),0x308479c,0x307e564,0x1537e4c,0x1537cd4,0x1537c9c,0x14952b4,0x14951b0,0x2066d90,0x1c207b4,0x734600,0x722530),
 'X100VI 1.31': ('Firmware на прочиеFuji/FPUPDATE.DAT','0d48d2ae26ac7ebab9b0e4cac56324807ec1ea8ae30df06b0b9e79066dc0a14a',(0x9c02bc,0x10e02bc),0x336d8a0,0x3367408,0x16092e0,0x16090f4,0x16090bc,0x1569aec,0x15699e8,0x211c1c8,0x1ccf740,0x53600,0x501f6),
}
DISPATCH = {
 'X-H2 5.30': (0x31367b0,0x17e2,0x3134f4c,0x3136890),
 'X-H2S 7.30': (0x34489fc,0x17e1,0x3447198,0x3448adc),
 'X-T5 4.31': (0x3075c40,0x17e4,0x30743dc,0x3075d20),
 'X100VI 1.31': (0x335e058,0x183a,0x335c7fc,0x335e4c8),
}

def run(name, c):
    path, expected, offsets, handler, wrapper, entry, norm, classify, ptr, u16, slot, threshold, table, values = c
    source = ROOT / path
    raw = source.read_bytes()
    before = hashlib.sha256(raw).hexdigest()
    if before != expected: raise ValueError(f'{name}: unexpected source hash {before}')
    decoded = raw.translate(base.TRANSLATION)
    im = dist.Image.__new__(dist.Image)
    im.blocks = []
    im.cs = dist.Cs(dist.CS_ARCH_ARM64, dist.CS_MODE_ARM)
    blocks = []
    for off in offsets:
        b = base.unpack_fflz(decoded, off)
        address = struct.unpack_from('<Q', b, 8)[0]
        im.blocks.append((address, b))
        blocks.append({'dat_offset':hex(off),'model_base':hex(address),'length':len(b),'sha256':hashlib.sha256(b).hexdigest()})
    def dis(a, size):
        return [{'pc':hex(x),'bytes':im.read(x,4).hex(),'instruction':op+' '+arg} for x,_,op,arg in im.instructions(a,a+size)]
    cases = [('baseline',2,4,3,False), ('swapped',4,2,3,False),
             ('sentinel_ff',2,4,255,False), ('normalization_class_1',2,35,3,False),
             ('unmapped_base',2,4,3,True)]
    runs=[]
    for label, field18, field20, selector, bad in cases:
        u=Uc(UC_ARCH_ARM64,UC_MODE_ARM)
        u.mem_map(0x1000,0x6000000-0x1000)
        for address,b in im.blocks: u.mem_write(address,b)
        u.mem_map(0x70000000,0x10000)
        u.mem_map(0x71000000,0x800000)
        u.reg_write(R.UC_ARM64_REG_SP,0x7000f000)
        u.reg_write(R.UC_ARM64_REG_X0,0x70002000)
        u.mem_write(0x70002000,struct.pack('<Q',0x70001000))
        u.mem_write(0x70001018,struct.pack('<I',field18))
        u.mem_write(0x70001020,struct.pack('<I',field20))
        u.mem_write(0x70001000,struct.pack('<I',0x89abcdef))
        u.mem_write(0x70001040,struct.pack('<I',0x10203040))
        u.mem_write(slot,struct.pack('<Q',0x90000000 if bad else 0x71000000))
        u.mem_write(threshold,struct.pack('<I',16))
        # Both row/column combinations are explicitly initialized; all other RAM is synthetic zero.
        u.mem_write(0x71000000+table+2*31+4,bytes([selector]))
        u.mem_write(0x71000000+table+4*31+2,bytes([5]))
        u.mem_write(0x71000000+values+2*3,struct.pack('<H',0x1234))
        u.mem_write(0x71000000+values+2*5,struct.pack('<H',0x5678))
        result={'case':label,'inputs':{'field_18':field18,'field_20':field20,'threshold':16,'base':hex(0x90000000 if bad else 0x71000000),'selector':selector},'pcs':[],'reads':[],'events':[]}
        def code(uc,pc,size,user):
            result['pcs'].append(hex(pc))
            if pc in (wrapper,entry,norm,classify,ptr,u16):
                result['events'].append({'pc':hex(pc),'x0':hex(uc.reg_read(R.UC_ARM64_REG_X0)),'x1':hex(uc.reg_read(R.UC_ARM64_REG_X1))})
            if pc==wrapper+0x18:
                result['lookup_return']=hex(uc.reg_read(R.UC_ARM64_REG_X0))
            if pc==handler+0x30:
                result['wrapper_return']=hex(uc.reg_read(R.UC_ARM64_REG_X0))
            if pc==handler+0x58:
                result['boundary']={'pc':hex(pc),'x0':hex(uc.reg_read(R.UC_ARM64_REG_X0)), 'saved_lookup_class':hex(struct.unpack('<I',bytes(uc.mem_read(uc.reg_read(R.UC_ARM64_REG_SP)+0x1a8,4)))[0])}
                uc.emu_stop()
        def read_hook(uc,access,address,size,value,user):
            if not 0x7000e000 <= address < 0x70010000:
                result['reads'].append({'pc':hex(uc.reg_read(R.UC_ARM64_REG_PC)),'address':hex(address),'size':size,'bytes':bytes(uc.mem_read(address,size)).hex()})
        def invalid(uc,access,address,size,value,user):
            result['invalid_access']={'pc':hex(uc.reg_read(R.UC_ARM64_REG_PC)),'address':hex(address),'size':size,'type':access}
            return False
        u.hook_add(UC_HOOK_CODE,code)
        u.hook_add(UC_HOOK_MEM_READ,read_hook)
        u.hook_add(UC_HOOK_MEM_INVALID,invalid)
        try: u.emu_start(handler,0,count=3000)
        except UcError as e: result['error']=str(e)
        runs.append(result)
    dispatcher, msg, callback, after_handler = DISPATCH[name]
    dispatch_runs=[]
    for label, code_value, callback_value in [('callback',msg,callback),('null_callback',msg,0),('other_message',0,callback)]:
        u=Uc(UC_ARCH_ARM64,UC_MODE_ARM)
        u.mem_map(0x1000,0x6000000-0x1000)
        for address,b in im.blocks: u.mem_write(address,b)
        u.mem_map(0x70000000,0x10000)
        u.reg_write(R.UC_ARM64_REG_SP,0x7000f000)
        u.reg_write(R.UC_ARM64_REG_X30,0x70003000)
        u.reg_write(R.UC_ARM64_REG_X0,code_value)
        u.reg_write(R.UC_ARM64_REG_X1,0x70002000)
        u.mem_write(0x70002000,struct.pack('<Q',callback_value))
        observation={'case':label,'message_code':hex(code_value),'synthetic_callback':hex(callback_value),'pcs':[],'handler_substituted':False}
        def dispatch_hook(uc,pc,size,user):
            observation['pcs'].append(hex(pc))
            if pc==handler:
                observation['handler_substituted']=True
                observation['handler_arg']=hex(uc.reg_read(R.UC_ARM64_REG_X0))
                uc.reg_write(R.UC_ARM64_REG_PC,uc.reg_read(R.UC_ARM64_REG_X30))
            elif pc==callback:
                observation['callback_reached']=True
                uc.emu_stop()
            elif pc==0x70003000:
                observation['dispatcher_returned']=True
                uc.emu_stop()
        u.hook_add(UC_HOOK_CODE,dispatch_hook)
        try: u.emu_start(dispatcher,0,count=1000)
        except UcError as e: observation['error']=str(e)
        dispatch_runs.append(observation)
    after=hashlib.sha256(source.read_bytes()).hexdigest()
    if before != after: raise ValueError(f'{name}: source changed during run')
    return {'source':path,'sha256_before':before,'sha256_after':after,'fflz':blocks,
            'addresses':{'handler':hex(handler),'wrapper':hex(wrapper),'second_entry':hex(entry),'normalizer':hex(norm),'classifier':hex(classify),'pointer_accessor':hex(ptr),'u16_accessor':hex(u16),'base_slot':hex(slot),'threshold':hex(threshold),'selector_table_offset':hex(table),'value_table_offset':hex(values)},
            'instructions':{'handler':dis(handler,0x5c),'wrapper':dis(wrapper,0x54),'lookup':dis(entry,0x60),'normalizer':dis(norm,0x38),'classifier':dis(classify,0x38),'pointer_accessor':dis(ptr,0x28),'u16_accessor':dis(u16,0x34),'dispatcher_callback':dis(after_handler-8,0x18)},
            'dispatcher':{'entry':hex(dispatcher),'handler_return':hex(after_handler),'callback_entry':hex(callback),'runs':dispatch_runs},'runs':runs}

if __name__ == '__main__':
    result={name:run(name,c) for name,c in CONFIG.items()}
    (HERE/'результаты.json').write_text(json.dumps(result,ensure_ascii=False,indent=2),encoding='utf-8')
    for name,r in result.items():
        print(name, [(x['case'],x.get('lookup_return'),x.get('wrapper_return'),x.get('boundary'),x.get('invalid_access')) for x in r['runs']])
