"""Четыре DAT читаются; условное исполнение связи paf -> paf_sub в Unicorn."""
from pathlib import Path
import sys, importlib.util, hashlib, struct, json

HERE = Path(__file__).resolve().parent
AN = HERE.parents[1]
ROOT = AN.parent
sys.path.insert(0, str(AN / 'инструменты'))
def load(name, path):
    spec = importlib.util.spec_from_file_location(name, path)
    mod = importlib.util.module_from_spec(spec); spec.loader.exec_module(mod); return mod
base = load('base', AN / 'анализ_файла.py')
dist = load('dist', AN / 'Распределение_систем_2026-11-01/исследовать_распределение.py')
from unicorn import Uc, UcError, UC_ARCH_ARM64, UC_MODE_ARM, UC_HOOK_CODE, UC_HOOK_MEM_READ, UC_HOOK_MEM_INVALID
from unicorn import arm64_const as R

# source, expected sha256, FFLZ offsets, producer start/call, getter, transport,
# receiver entries, receive, dispatcher, selected sub-handler, payload stack offset
CFG = {
 'X-H2 5.30': (base.SOURCE, 'be47168cb075ef726e67cb4bb08175a896047a3b0de2bcb6e65333b22cfcb203', (0x300274,0x840274), 0x3135d7c,0x3135d8c,0x14ce514,0x14cf124,(0x31372b0,0x31372f8),0x14cf354,0x31367b0,0x314530c,0x70,0x17e2,0x313754c),
 'X-H2S 7.30': (ROOT/'Firmware на прочиеFuji/FWUP0027.DAT','87c566c1ff6343e4c7463a4ef968183f41d1f24cc63d610433d3a387b13f731b',(0x300274,0x840274),0x3447fc8,0x3447fd8,0x17ee0a8,0x17eecb8,(0x34494fc,0x3449544),0x17eeee8,0x34489fc,0x34573e0,0x70,0x17e1,0x3449798),
 'X-T5 4.31': (ROOT/'Firmware на прочиеFuji/FWUP0030.DAT','790d6deecf26766188b0e506e40645e6b816addfeba39a52334349405421724e',(0x300274,0x820274),0x307520c,0x307521c,0x14c6304,0x14c6f88,(0x3076740,0x3076788),0x14c71b8,0x3075c40,0x308479c,0x70,0x17e4,0x30769dc),
 'X100VI 1.31': (ROOT/'Firmware на прочиеFuji/FPUPDATE.DAT','0d48d2ae26ac7ebab9b0e4cac56324807ec1ea8ae30df06b0b9e79066dc0a14a',(0x9c02bc,0x10e02bc),0x335d360,0x335d370,0x159a554,0x159b220,(0x335efa4,0x335efec),0x159b450,0x335e058,0x336d8a0,0x58,0x183a,0x335f258),
}
def run_one(name, cfg):
    path, expected, offsets, start, call, getter, send, entries, receive, dispatch, target, off, code, wrapper = cfg
    raw = path.read_bytes(); before = hashlib.sha256(raw).hexdigest(); assert before == expected
    data = raw.translate(base.TRANSLATION)
    im = dist.Image.__new__(dist.Image); im.blocks=[]; im.cs=dist.Cs(dist.CS_ARCH_ARM64,dist.CS_MODE_ARM)
    for o in offsets:
        b=base.unpack_fflz(data,o); a=struct.unpack_from('<Q',b,8)[0]; im.blocks.append((a,b))
    def ins(a,b):
        return [{'address':hex(x), 'bytes':im.read(x,4).hex(), 'instruction':op+' '+args} for x,_,op,args in im.instructions(a,b)]
    def machine():
        u=Uc(UC_ARCH_ARM64,UC_MODE_ARM); u.mem_map(0x1000,0x6000000-0x1000)
        for a,b in im.blocks: u.mem_write(a,b)
        u.mem_map(0x70000000,0x10000); u.reg_write(R.UC_ARM64_REG_SP,0x7000f000)
        return u
    experiments=[]
    for selector in (0,1):
        u=machine(); u.reg_write(R.UC_ARM64_REG_X20,selector)
        payload=bytes(range(0x10,0x28)); u.mem_write(0x7000f000+off,payload)
        captured={}; trace=[]
        def sender_hook(uc,pc,size,user):
            if pc in (start,call,wrapper,getter,send): trace.append(hex(pc))
            if pc==getter:
                uc.reg_write(R.UC_ARM64_REG_X0,0x2a); uc.reg_write(R.UC_ARM64_REG_PC,uc.reg_read(R.UC_ARM64_REG_X30))
            elif pc==send:
                ptr=uc.reg_read(R.UC_ARM64_REG_X1); size=24 if name.startswith('X100') else 16
                header=bytes(uc.mem_read(ptr,size)); pp=struct.unpack_from('<Q',header,16 if size==24 else 8)[0]
                captured.update(queue=uc.reg_read(R.UC_ARM64_REG_X0),message=header.hex(),payload=bytes(uc.mem_read(pp,32)).hex(),payload_pointer=hex(pp))
                uc.emu_stop()
        u.hook_add(UC_HOOK_CODE,sender_hook); u.emu_start(start,0,count=1000)
        assert captured and int.from_bytes(bytes.fromhex(captured['message'])[:2],'little')==code
        assert captured['queue']==(0xb6 if name.startswith('X100') else 0x93)+selector
        v=machine(); recv={}; rtrace=[]
        def receiver_hook(uc,pc,size,user):
            if pc in (entries[selector],receive,dispatch,target): rtrace.append(hex(pc))
            if pc==receive:
                recv.update(queue=uc.reg_read(R.UC_ARM64_REG_X0), buffer=hex(uc.reg_read(R.UC_ARM64_REG_X1)),wait=hex(uc.reg_read(R.UC_ARM64_REG_X2)))
                # Только код сообщения передаётся модели вручную; контекст и данные не восстанавливаются.
                uc.mem_write(uc.reg_read(R.UC_ARM64_REG_X1),bytes.fromhex(captured['message'])[:2])
                uc.reg_write(R.UC_ARM64_REG_X0,0); uc.reg_write(R.UC_ARM64_REG_PC,uc.reg_read(R.UC_ARM64_REG_X30))
            elif pc==target:
                recv['subhandler_argument']=hex(uc.reg_read(R.UC_ARM64_REG_X0)); uc.emu_stop()
        v.hook_add(UC_HOOK_CODE,receiver_hook); v.emu_start(entries[selector],0,count=1000)
        assert recv.get('subhandler_argument') and recv['queue']==captured['queue']
        experiments.append({'selector':selector,'sender_trace':trace,'sender':captured,'receiver_trace':rtrace,'receiver':recv})
    # Независимое продолжение: синтетическая двухуровневая структура вместо
    # недоказанной доставки контекста. Останов на входе второго BL.
    handler_runs=[]
    first_call=target+0x2c
    first_dest=int(im.instructions(first_call,first_call+4)[0][3].lstrip('#'),0)
    second_call=first_dest+0x14
    second_dest=int(im.instructions(second_call,second_call+4)[0][3].lstrip('#'),0)
    for label,ptr,a,b in [('baseline',0x70001000,0x12345678,0x9abcdef0),
                          ('swapped',0x70001000,0x9abcdef0,0x12345678),
                          ('null_pointer',0,0x12345678,0x9abcdef0)]:
        v=machine(); v.reg_write(R.UC_ARM64_REG_X0,0x70002000)
        v.mem_write(0x70002000,struct.pack('<Q',ptr))
        v.mem_write(0x70001000+0x18,struct.pack('<I',a))
        v.mem_write(0x70001000+0x20,struct.pack('<I',b))
        obs={'case':label,'input_root':'0x70002000','root_pointer':hex(ptr),
             'field_18':hex(a),'field_20':hex(b),'reads':[],'pcs':[]}
        def read_hook(uc,access,address,size,value,user):
            if 0x1000 <= address < 0x7000e000:
                obs['reads'].append({'pc':hex(uc.reg_read(R.UC_ARM64_REG_PC)),
                                     'address':hex(address),'size':size,
                                     'bytes':bytes(uc.mem_read(address,size)).hex()})
        def invalid_hook(uc,access,address,size,value,user):
            obs['invalid_read']={'pc':hex(uc.reg_read(R.UC_ARM64_REG_PC)),
                                 'address':hex(address),'size':size}
            return False
        def code_hook(uc,pc,size,user):
            obs['pcs'].append(hex(pc))
            if pc==first_dest:
                obs['first_bl_args']=[hex(uc.reg_read(R.UC_ARM64_REG_X0)),hex(uc.reg_read(R.UC_ARM64_REG_X1))]
            if pc==second_dest:
                obs['second_bl_args']=[hex(uc.reg_read(R.UC_ARM64_REG_X0)),hex(uc.reg_read(R.UC_ARM64_REG_X1))]
                uc.emu_stop()
        v.hook_add(UC_HOOK_MEM_READ,read_hook); v.hook_add(UC_HOOK_MEM_INVALID,invalid_hook)
        v.hook_add(UC_HOOK_CODE,code_hook)
        try: v.emu_start(target,0,count=100)
        except UcError as exc: obs['error']=str(exc)
        if ptr:
            assert obs['first_bl_args']==[hex(a),hex(b)]
            assert obs['second_bl_args']==[hex(b),hex(a)]
        else:
            assert 'invalid_read' in obs and 'first_bl_args' not in obs
        handler_runs.append(obs)
    # Первый qword скопированной нагрузки указывает на инструкции. Их исполнение
    # здесь отдельное: перенос указателя из сообщения в контекст не доказан.
    callback=struct.unpack_from('<Q',bytes.fromhex(captured['payload']))[0]
    callback_call=callback+0x14
    callback_dest=int(im.instructions(callback_call,callback_call+4)[0][3].lstrip('#'),0)
    callback_result={'entry':hex(callback),'target':hex(callback_dest),'pcs':[]}
    v=machine()
    def callback_hook(uc,pc,size,user):
        callback_result['pcs'].append(hex(pc))
        if pc==callback_dest:
            callback_result['args']=[hex(uc.reg_read(getattr(R,'UC_ARM64_REG_X'+str(i)))) for i in range(3)]
            uc.emu_stop()
    v.hook_add(UC_HOOK_CODE,callback_hook); v.emu_start(callback,0,count=100)
    assert callback_result.get('args') and callback_result['args'][1:]==['0x0','0x0']
    callback_result['instructions']=ins(callback,callback+0x18)
    after=hashlib.sha256(path.read_bytes()).hexdigest(); assert before==after
    return {'source':str(path.relative_to(ROOT)), 'sha256_before':before,'sha256_after':after,
            'fflz':[{'dat_offset':hex(o),'model_base':hex(a),'uncompressed_size':len(b),'sha256':hashlib.sha256(b).hexdigest()} for o,(a,b) in zip(offsets,im.blocks)],
            'direct_bl_to_wrapper_candidates':[hex(c) for c,_ in im.calls({wrapper})],
            'producer_instructions':ins(start,call+4),'wrapper_instructions':ins(wrapper,wrapper+0x38),
            'receiver_instructions':[ins(e,e+0x48) for e in entries], 'dispatcher_instructions':ins(dispatch,dispatch+0x110),
            'subhandler_entry':hex(target),'subhandler_instructions':ins(target,target+0x30),
            'first_callee':hex(first_dest),'first_callee_instructions':ins(first_dest,first_dest+0x18),
            'second_callee':hex(second_dest),'subhandler_runs':handler_runs,
            'callback_independent':callback_result,'experiments':experiments}
results={name:run_one(name,cfg) for name,cfg in CFG.items()}
(HERE/'результаты.json').write_text(json.dumps(results,ensure_ascii=False,indent=2),encoding='utf-8')
print(json.dumps({n:{'source':v['source'],'sha256_before':v['sha256_before'],'sha256_after':v['sha256_after'],'experiments':v['experiments']} for n,v in results.items()},ensure_ascii=False,indent=2))
