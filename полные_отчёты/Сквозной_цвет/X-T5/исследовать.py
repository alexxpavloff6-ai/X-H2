"""X-T5 4.31: оригинальные фрагменты ARM64; DAT исключительно читается."""
from pathlib import Path
import hashlib, importlib.util, json, struct, sys

HERE = Path(__file__).resolve().parent
ROOT = HERE.parents[2]
ANALYSIS = ROOT / 'Анализ_прошивки'
sys.path.insert(0, str(ANALYSIS / 'инструменты'))
from unicorn import Uc, UC_ARCH_ARM64, UC_MODE_ARM, UC_HOOK_MEM_WRITE
from unicorn import arm64_const as R
from capstone import Cs, CS_ARCH_ARM64, CS_MODE_ARM

def load(name, path):
    spec = importlib.util.spec_from_file_location(name, path)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module
base = load('base', ANALYSIS / 'анализ_файла.py')
dictionary = load('dictionary', ANALYSIS / 'Сравнение_камер/сравнить_словари.py')
source = ROOT / 'Firmware на прочиеFuji/FWUP0030.DAT'
raw = source.read_bytes()
sha = hashlib.sha256(raw).hexdigest()
assert sha == '790d6deecf26766188b0e506e40645e6b816addfeba39a52334349405421724e'
data = raw.translate(base.TRANSLATION)
a = base.unpack_fflz(data, 0x300274)
b = base.unpack_fflz(data, 0x820274)
u = Uc(UC_ARCH_ARM64, UC_MODE_ARM)
for address, block in [(0x40000, data[0x60274:0x7e5b4]), (0x1101000, a), (0x28eb000, b)]:
    size = (len(block)+4095)&~4095
    u.mem_map(address, size)
    u.mem_write(address, block)
aend = 0x1101000 + ((len(a)+4095)&~4095)
bend = 0x28eb000 + ((len(b)+4095)&~4095)
u.mem_map(aend, 0x28eb000-aend)
u.mem_map(bend, 0x6000000-bend)
u.mem_map(0x27008000, 0x100000)
u.mem_write(0x27008000, data[0xc0274:0xc0274+0xc6c00])
u.mem_write(0x2066d90, struct.pack('<Q', 0x27008000))
u.mem_map(0x60000000, 0x40000)
u.mem_map(0x70000000, 0x10000)
u.mem_map(0xff96c000, 0x4000)
REG = [getattr(R, 'UC_ARM64_REG_X'+str(i)) for i in range(31)]
STOP = 0x70000000

def put(address, value): u.mem_write(address, struct.pack('<I', value & 0xffffffff))
def get(address): return struct.unpack('<I', u.mem_read(address, 4))[0]
def execute(start, end=STOP, registers=None):
    for reg in REG: u.reg_write(reg, 0)
    u.mem_write(0x7000d000, bytes(0x3000))
    u.reg_write(R.UC_ARM64_REG_SP, 0x7000f000)
    u.reg_write(R.UC_ARM64_REG_X30, STOP)
    for i, value in (registers or {}).items(): u.reg_write(REG[i], value)
    u.emu_start(start, end, count=200000, timeout=1000000)
    pc = u.reg_read(R.UC_ARM64_REG_PC)
    if pc != end: raise RuntimeError(f'{start:#x}: PC {pc:#x}, ожидался {end:#x}')
    return u.reg_read(R.UC_ARM64_REG_X0) & 0xffffffff

def lookup(name):
    row = dictionary.locate(b, 0x28eb000, name)
    return {'name': name, **row, 'record_address': hex(0x28eb000+int(row['record_offset'],16)), 'string_address': hex(0x28eb000+int(row['string_offset'],16))}
labels = ['EXTRA_DARK','SUPER_DARK','DARK','MID_DARK','STANDARD','MID_THIN','THIN','SUPER_THIN','EXTRA_THIN']
dicts = {n: lookup(n) for n in ['UI_SETP_FILM_SIM','UI_SETP_STILLCOLOR','UI_FILM_SIM_CLASSIC_CHROME'] + ['UI_STILLCOLOR_'+n for n in labels]}
assert [dicts['UI_STILLCOLOR_'+n]['value'] for n in labels] == list(range(9))
root = 0x1bb1a30
film_table, color_table = [struct.unpack_from('<Q',a,root-0x1101000+i*8)[0] for i in (1699,1742)]
assert (film_table,color_table)==(0x1759c70,0x176eb80)
def rows(table,n): return [list(struct.unpack_from('<4I',a,table-0x1101000+i*16)) for i in range(n)]
film_rows=rows(film_table,26); color_rows=rows(color_table,9)
assert rows(color_table+9*16,1)[0]==[0xffff]*4

def convert(parameter, value, out=3):
    put(0x20007ec,0)
    v=execute(0x12e48b0,registers={0:parameter,1:value,2:0,3:out})
    return v,get(0x20007ec)

writes=[]
def capture(uc, access, address, size, value, _):
    if address in (0xff96c634,0xff96c638):
        writes.append({'address':hex(address),'size':size,'value':hex(value),'pc':hex(uc.reg_read(R.UC_ARM64_REG_PC))})
hook=u.hook_add(UC_HOOK_MEM_WRITE,capture,begin=0xff96c000,end=0xff96ffff)
frame=0x60000000; params=0x60008000; intermediate=0x60010000; context=0x60012000; general=0x60014000; registers=0x60018000; tmp=0x6001a000
runs=[]
for name, film in [('STANDARD',0),('CLASSIC_CHROME',14),('ETERNA',18),('REALA',17)]:
    for ui in range(9):
        for p, size in [(frame,0x1000),(params,0x6000),(intermediate,0x1000),(context,0x1000),(general,0x2000),(registers,0x1000)]: u.mem_write(p,bytes(size))
        put(0x20007ec,0); put(0x25bcccc,0xdeadbeef)
        # Реальный вызов wrapper-конвертера и MODE-сохранителя без подмены инструкций.
        execute(0x132ae38,0x132ae4c,{1:film})
        state=get(0x25bcccc); error=get(0x20007ec)
        assert error==0 and state==film_rows[film][2]
        c,err=convert(1742,ui); repr4,err4=convert(1742,ui,4)
        assert err==err4==0 and c==color_rows[ui][2] and repr4==color_rows[ui][3]
        signed=struct.unpack('<i',struct.pack('<I',repr4))[0]
        # Состояние вручную передано на вызов сеттера: автоматический мост не доказан.
        execute(0x1559350,registers={0:frame,1:state})
        execute(0x2d955e8,0x2d955f8,{21:frame,20:params})
        assert get(params+0x3a00)==state
        # Отдельный оригинальный путь копирует цвет из синтетической входной записи.
        # Происхождение самой записи +0x50 из интерфейса не установлено.
        put(tmp+0x150,c)
        execute(0x2d9e76c,0x2d9e774,{20:tmp+0x100,19:params})
        assert get(params+0x39fc)==c
        execute(0x2d2edb0,0x2d2edb8,{20:params,19:intermediate})
        execute(0x2d2ede4,0x2d2edec,{20:params,19:intermediate})
        assert get(intermediate+0xc)==c and get(intermediate+0x20)==state
        for off,val in [(0x100,0),(0x12c,1),(0x124,18),(0x128,18),(0x10c,8),(0x17c,2)]: put(context+off,val)
        execute(0x2e75160,0x2e7516c,{19:context,20:intermediate})
        execute(0x2e751c8,0x2e751dc,{19:context,20:intermediate})
        mode=get(context+0x130); index=get(context+0x13c)
        execute(0x2e5f410,registers={0:context,1:tmp})
        selector=bytes(u.mem_read(tmp,1))[0]
        execute(0x2e57910,0x2e57928,{19:context,21:general+0x96c})
        coefficients=list(struct.unpack('<4h',u.mem_read(general+0xb46,8)))
        execute(0x2e57f0c,registers={0:general,1:0x80,2:registers})
        packed=list(struct.unpack('<4H',u.mem_read(registers+0x1ec,8)))
        writes.clear(); execute(0x2e57f38,registers={0:0x80,1:registers})
        assert len(writes)==2
        runs.append({'film':name,'film_ui':film,'mode_state':state,'frame_c0':get(frame+0xc0),'params_3a00':get(params+0x3a00),'ui_color':ui,'color_name':labels[ui], 'representation_4_signed':signed,'nominal_display':signed//10,'color_native':c,'intermediate_mode_20':get(intermediate+0x20),'intermediate_color_c':get(intermediate+0xc),'color_mode_130':mode,'color_index_13c':index,'selector':selector,'gain':data[0xc0274+0xaf50+index], 'coefficients':coefficients,'packed':packed,'mmio':list(writes)})
        assert index==8-ui
writes.clear(); execute(0x2e57f38,registers={0:0,1:registers}); assert not writes
u.hook_del(hook)
# Проверить ветку сравнения без изменения сохранённого MODE.
put(0x2003300,14); put(0x2001080,14); put(0x25bcccc,0x12345678)
execute(0x132a978,0x132a990)
assert get(0x25bcccc)==0x12345678
# При неравенстве ветвь действительно приводит к setter; стоп перед дальнейшими инструкциями.
put(0x2003300,14); put(0x2001080,0); put(0x25bcccc,0x12345678); put(0x20007ec,0)
execute(0x132a978,0x132ae4c)
assert get(0x25bcccc)==13 and get(0x20007ec)==0
windows=[(0x132a978,0x132a990),(0x132ae38,0x132ae4c),(0x1135948,0x113595c),(0x12ed180,0x12ed1e8),(0x1559348,0x1559358),(0x2d955e8,0x2d955f8),(0x2d9e76c,0x2d9e774),(0x2d2edb0,0x2d2edb8),(0x2d2ede4,0x2d2edec),(0x2e75160,0x2e7516c),(0x2e751c8,0x2e751dc),(0x2e743b8,0x2e74468),(0x2e57910,0x2e57928)]
cs=Cs(CS_ARCH_ARM64,CS_MODE_ARM)
asm=[]
for start,end in windows:
    block,ba=(a,0x1101000) if start<0x28eb000 else (b,0x28eb000)
    asm.append(f'\n; {start:#x}..{end:#x}')
    for ins in cs.disasm(block[start-ba:end-ba],start): asm.append(f'{ins.address:08x}  {ins.mnemonic:8} {ins.op_str}')
(HERE/'фрагменты.asm').write_text('\n'.join(asm)+'\n',encoding='utf-8')
result={'source':str(source.relative_to(ROOT)),'sha256':sha,'block_sha256':{'a':hashlib.sha256(a).hexdigest(),'b':hashlib.sha256(b).hexdigest()},'mapping':'модельные адреса FFLZ, шаблон DAT 0xc0274 по 0x27008000, MMIO — RAM','dictionary':dicts,'table_root':hex(root),'film_table':hex(film_table),'film_rows':film_rows,'color_table':hex(color_table),'color_rows':color_rows,'comparison':{'new_global':'0x2003300','old_global':'0x2001080','equal_preserves_state':True,'different_14_state':13},'runs':runs,'zero_mask_writes':0,'caveats':['Ручной перенос state в setter кадра и color во входную запись +0x50','Для X-T5 поле film +0x3a00, не X-H2 +0x39b8','Номинальное меню = representation 4 / 10; независимого чтения экрана нет','MMIO виртуально, съёмка и фактическая достижимость не проверены']}
assert hashlib.sha256(source.read_bytes()).hexdigest()==sha
result['source_unchanged']=True
(HERE/'результаты.json').write_text(json.dumps(result,ensure_ascii=False,indent=2)+'\n',encoding='utf-8')
print(json.dumps({'sha256':sha,'runs':len(runs),'classic': [r for r in runs if r['film']=='CLASSIC_CHROME' and r['nominal_display'] in (-4,0,2,4)]},ensure_ascii=False,indent=2))
