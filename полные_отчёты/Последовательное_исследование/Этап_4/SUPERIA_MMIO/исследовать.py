"""Исходные ARM64-фрагменты четырёх DAT в Unicorn; никаких физических MMIO."""
from pathlib import Path
import hashlib, importlib.util, json, struct, sys
sys.dont_write_bytecode = True
HERE = Path(__file__).resolve().parent
ANALYSIS = HERE.parents[2]
ROOT = ANALYSIS.parent
sys.path.insert(0, str(ANALYSIS / 'инструменты'))
spec = importlib.util.spec_from_file_location('calc', ANALYSIS / 'Единый_глубокий_анализ/сопоставить_цветовые_расчёты.py')
calc = importlib.util.module_from_spec(spec); spec.loader.exec_module(calc)
from unicorn import Uc, UC_ARCH_ARM64, UC_MODE_ARM, UC_HOOK_MEM_WRITE
from unicorn import arm64_const as R

# low-level loaded block, translator offset, packer, mask dispatcher
CONFIG = {
 'X-H2': (0x60274, 0x1e340, 0x58ac30, 0x13777d0, 0x2d2f4f8),
 'X-H2S': (0x60274, 0x1e340, 0x5859a8, 0x16953b0, 0x3045b98),
 'X-T5': (0x60274, 0x1e340, 0x588f2c, 0x13747a0, 0x2c6e1c4),
 'X100VI': (0x7f2bc, 0x70000, 0x5bfee4, 0x145fb28, 0x2f34cd8),
}
SRC, OUT, INPUT, REGS, STOP = 0x60000000, 0x60010000, 0x60020000, 0x60030000, 0x70000000
TARGETS = (0xff96c634, 0xff96c638)
result = {}
for model, (lo, ln, mode_off, packer, dispatcher) in CONFIG.items():
    selector, calculate, pointer = calc.CONFIG[model]
    rel, expected, ao, bo, _, _, template, _ = calc.tables.FILES[model]
    path = ROOT / rel
    raw = path.read_bytes(); before = hashlib.sha256(raw).hexdigest(); assert before == expected
    decoded = raw.translate(calc.tables.base.TRANSLATION)
    a, b = calc.tables.base.unpack_fflz(decoded, ao), calc.tables.base.unpack_fflz(decoded, bo)
    base_a, base_b = struct.unpack_from('<Q', a, 8)[0], struct.unpack_from('<Q', b, 8)[0]
    u = Uc(UC_ARCH_ARM64, UC_MODE_ARM)
    u.mem_map(0x40000, 0x5fc0000)
    for address, block in ((0x40000, decoded[lo:lo+ln]), (base_a, a), (base_b, b)): u.mem_write(address, block)
    u.mem_map(0x27008000, 0x100000); u.mem_write(0x27008000, decoded[template:template+0xc6c00]); u.mem_write(pointer, struct.pack('<Q', 0x27008000))
    u.mem_map(SRC, 0x40000); u.mem_map(STOP, 0x10000); u.mem_map(0xff000000, 0x1000000)
    events = []
    def hook(uc, access, address, size, value, user):
        events.append({'pc': hex(uc.reg_read(R.UC_ARM64_REG_PC)), 'address': hex(address), 'size': size, 'value': hex(value)})
    u.hook_add(UC_HOOK_MEM_WRITE, hook, begin=0xff000000, end=0xffffffff)
    def run(entry, *args):
        for i in range(31): u.reg_write(getattr(R, 'UC_ARM64_REG_X'+str(i)), 0)
        for i, arg in enumerate(args): u.reg_write(getattr(R, 'UC_ARM64_REG_X'+str(i)), arg)
        u.reg_write(R.UC_ARM64_REG_X30, STOP); u.reg_write(R.UC_ARM64_REG_SP, STOP+0xf000)
        u.emu_start(entry, STOP, timeout=5000000, count=200000)
        assert u.reg_read(R.UC_ARM64_REG_PC) == STOP, (model, hex(entry), hex(u.reg_read(R.UC_ARM64_REG_PC)))
    u.mem_write(OUT, bytes(0x1000)); run(base_b+mode_off, OUT, 19)
    code = struct.unpack('<I', u.mem_read(OUT, 4))[0]
    context = {0x100:0, 0x12c:1, 0x130:code, 0x124:18, 0x128:18, 0x13c:4, 0x10c:8, 0x17c:2}
    for offset, value in context.items(): u.mem_write(SRC+offset, struct.pack('<I', value))
    u.mem_write(OUT, bytes(0x1000)); run(selector, SRC, OUT); selected = u.mem_read(OUT, 1)[0]
    assert (code, selected) == (10, 8)
    rows = []
    for index in (4,5,6):
        u.mem_write(SRC+0x13c, struct.pack('<I', index)); u.mem_write(OUT, bytes(0x1000)); run(calculate, SRC, OUT)
        coeff = list(struct.unpack('<4h', u.mem_read(OUT+0x3c, 8)))
        upper_cases = []
        for upper in (0, 0xa000, 0xe000):
            u.mem_write(INPUT, bytes(0x1000)); u.mem_write(REGS, bytes(0x1000))
            # Researcher transfer between independently executed functions.
            u.mem_write(INPUT+0x1da, struct.pack('<4h', *coeff)); u.mem_write(REGS+0x1ec, struct.pack('<4H', *([upper]*4)))
            run(packer, INPUT, REGS)
            fields = list(struct.unpack('<4H', u.mem_read(REGS+0x1ec, 8)))
            assert fields == [upper | (v & 0x1fff) for v in coeff]
            words = list(struct.unpack('<2I', struct.pack('<4H', *fields)))
            masks = []
            for mask in (0, 0x40, 0x80, 0x81, 0x100, 0x100000):
                events.clear(); run(dispatcher, mask, REGS)
                chosen = [x for x in events if int(x['address'],16) in TARGETS]
                expected_writes = [(hex(addr), 4, hex(word)) for addr,word in zip(TARGETS,words)] if mask in (0x80,0x81) else []
                assert [(x['address'],x['size'],x['value']) for x in chosen] == expected_writes
                masks.append({'mask':hex(mask), 'target_writes':chosen, 'all_virtual_writes_count':len(events)})
            upper_cases.append({'initial_upper_each':hex(upper), 'packed_u16':[hex(v) for v in fields], 'packed_words':[hex(v) for v in words], 'masks':masks})
        rows.append({'index':index, 'four_signed16':coeff, 'upper_cases':upper_cases})
    controls=[]
    for values in ((0,-1,4095,-4096),(-4097,4096,-32768,32767)):
        for upper in (0,0xa000,0xe000):
            u.mem_write(INPUT,bytes(0x1000)); u.mem_write(REGS,bytes(0x1000))
            u.mem_write(INPUT+0x1da,struct.pack('<4h',*values)); u.mem_write(REGS+0x1ec,struct.pack('<4H',*([upper]*4)))
            run(packer,INPUT,REGS); fields=list(struct.unpack('<4H',u.mem_read(REGS+0x1ec,8)))
            assert fields == [upper | (max(-4096,min(4095,v)) & 0x1fff) for v in values]
            controls.append({'input_signed16':list(values),'initial_upper_each':hex(upper),'packed_u16':[hex(x) for x in fields]})
    after=hashlib.sha256(path.read_bytes()).hexdigest(); assert before==after
    result[model]={'dat':str(rel),'sha256_before':before,'sha256_after':after,'decoded_blocks_sha256':[hashlib.sha256(a).hexdigest(),hashlib.sha256(b).hexdigest()], 'template_dat_offset':hex(template),'translator':hex(base_b+mode_off),'selector':hex(selector),'calculator':hex(calculate),'packer':hex(packer),'dispatcher':hex(dispatcher),'context':{hex(k):v for k,v in context.items()},'mode':19,'translated_code':code,'selected':selected,'runs':rows,'sign_saturation_controls':controls}
    print(model, [(r['index'],r['four_signed16'],r['upper_cases'][0]['packed_words']) for r in rows], flush=True)
(HERE/'результаты.json').write_text(json.dumps(result,ensure_ascii=False,indent=2)+'\n',encoding='utf-8')
