"""Исследование X100VI 1.31: только чтение DAT, ARM64 в Unicorn."""
from pathlib import Path
import csv, hashlib, importlib.util, json, struct, sys

HERE = Path(__file__).resolve().parent
ROOT = HERE.parents[2]
PROJECT = ROOT.parent
sys.path.insert(0, str(ROOT / 'инструменты'))
spec = importlib.util.spec_from_file_location('base', ROOT / 'анализ_файла.py')
base = importlib.util.module_from_spec(spec); spec.loader.exec_module(base)
from unicorn import Uc, UC_ARCH_ARM64, UC_MODE_ARM, UC_HOOK_MEM_WRITE
from unicorn.arm64_const import *

path = PROJECT / 'Firmware на прочиеFuji' / 'FPUPDATE.DAT'
raw = path.read_bytes()
sha = hashlib.sha256(raw).hexdigest()
assert sha == '0d48d2ae26ac7ebab9b0e4cac56324807ec1ea8ae30df06b0b9e79066dc0a14a'
dat = raw.translate(base.TRANSLATION)
a = base.unpack_fflz(dat, 0x9c02bc)
b = base.unpack_fflz(dat, 0x10e02bc)
a_base, b_base = struct.unpack_from('<Q', a, 8)[0], struct.unpack_from('<Q', b, 8)[0]
assert (a_base, b_base) == (0x11c1000, 0x2b8f000)
uc = Uc(UC_ARCH_ARM64, UC_MODE_ARM)
# Блоки пересекаются в конце первого; второй загружен последним.
start = a_base & -4096
end = (max(a_base+len(a), b_base+len(b))+4095)&-4096
uc.mem_map(start, end-start)
uc.mem_write(a_base, a); uc.mem_write(b_base, b)
# Низкий модуль: отображение исходных XOR-байтов с разницей DAT-RAM 0x3f2bc.
uc.mem_map(0x40000, 0x70000)
uc.mem_write(0x40000, dat[0x7f2bc:0xef2bc])
assert dat[0xde01c:0xde024] == bytes.fromhex('010000b9c0035fd6')
uc.mem_map(0x27000000, 0x400000)
uc.mem_write(0x27000000, dat[0x6602bc:0xa002bc])
uc.mem_write(0x211c1c8, struct.pack('<Q', 0x27000000))
uc.mem_map(0x60000000, 0x40000)
uc.mem_map(0x70000000, 0x10000)
uc.mem_map(0xff96c000, 0x1000)
p, tmp, dest, img, stop = 0x60000000,0x60010000,0x60020000,0x60030000,0x70000000
writes=[]
def hook(uc, access, address, size, value, data):
    writes.append({'address':hex(address),'size':size,'value':hex(value)})
uc.hook_add(UC_HOOK_MEM_WRITE, hook, begin=0xff96c000, end=0xff96cfff)
def call(addr, args):
    for j in range(8): uc.reg_write(globals()[f'UC_ARM64_REG_X{j}'], args[j] if j<len(args) else 0)
    uc.reg_write(UC_ARM64_REG_X30,stop); uc.reg_write(UC_ARM64_REG_SP,0x7000f000)
    uc.emu_start(addr,stop,count=200000)
    assert uc.reg_read(UC_ARM64_REG_PC)==stop,hex(addr)
def clear(addr): uc.mem_write(addr,bytes(0x1000))
def put(addr,value): uc.mem_write(addr,struct.pack('<I',value))
def get(addr): return struct.unpack('<I',uc.mem_read(addr,4))[0]

put(0x20b44c4,0)
call(0x13c9930,[1756,14,0,3])
menu_mode=uc.reg_read(UC_ARM64_REG_X0)&0xffffffff
menu_error=get(0x20b44c4)
assert (menu_mode,menu_error)==(13,0)

# Проверить MODE через реальную таблицу переходов, а не вывод по сходству.
mode_map=[]
for mode in range(24):
    clear(p); call(0x314eee4,[p,mode]); mode_map.append({'mode':mode,'color_code':get(p)})
cc=next(r['color_code'] for r in mode_map if r['mode']==menu_mode)
keys=list(struct.unpack_from('<4I',b,0x365f538-b_base+5*16))
source=list(struct.unpack_from('<4H',dat,0x6602bc+keys[0]))
rows=[]
for native in range(9):
    clear(p); clear(tmp); clear(dest); clear(img)
    call(0x314f388,[tmp,native,1,0]); index=get(tmp)
    for off,val in [(0x12c,1),(0x130,cc),(0x124,0x12),(0x128,0x12),(0x13c,index),(0x10c,8),(0x17c,2)]: put(p+off,val)
    call(0x313a1c0,[p,tmp]); selector=uc.mem_read(tmp,1)[0]
    call(0x313cef8,[p,dest])
    values=list(struct.unpack('<4h',uc.mem_read(dest+0x1da,8)))
    call(0x145fb28,[dest,img])
    fields=list(struct.unpack('<4H',uc.mem_read(img+0x1ec,8)))
    writes.clear(); call(0x145fbdc,[img]); observed=list(writes)
    gain=dat[0x6602bc+struct.unpack_from('<I',b,0x365f858-b_base+index*4)[0]]
    rows.append({'native':native,'index':index,'gain':gain,'selector':selector,'coefficients':values,'packed_fields':fields,'writes':observed})
assert cc==8 and keys==[0xb058,0xb05a,0xb05c,0xb05e] and source==[885,859,8182,8180]
assert all(r['selector']==6 for r in rows)
assert all(r['packed_fields']==[v&0x1fff for v in r['coefficients']] for r in rows)
for row in rows:
    assert row['index']==8-row['native']
    assert row['coefficients']==[(n*row['gain']*128*64)>>20 for n in (885,-10,859,-12)]
    assert [w['address'] for w in row['writes']]==['0xff96c634','0xff96c638']
    assert [int(w['value'],16) for w in row['writes']]==[row['packed_fields'][0]|row['packed_fields'][1]<<16,row['packed_fields'][2]|row['packed_fields'][3]<<16]
pack_cases=[]
for upper in (0,0xa000,0xe000):
    for values in ((885,-10,859,-12),(4095,-4096,4096,-4097)):
        clear(dest);clear(img)
        uc.mem_write(dest+0x1da,struct.pack('<4h',*values))
        uc.mem_write(img+0x1ec,struct.pack('<4H',*[upper]*4))
        call(0x145fb28,[dest,img])
        fields=list(struct.unpack('<4H',uc.mem_read(img+0x1ec,8)))
        assert fields==[upper|(max(-4096,min(4095,v))&0x1fff) for v in values]
        pack_cases.append({'input':values,'upper':hex(upper),'fields':fields})
assert hashlib.sha256(path.read_bytes()).hexdigest()==sha
result={'source_sha256':sha,'blocks':[{'dat':hex(0x9c02bc),'base':hex(a_base)},{'dat':hex(0x10e02bc),'base':hex(b_base)}], 'menu_conversion':{'function':'0x13c9930','args':[1756,14,0,3],'mode':menu_mode,'error':menu_error},'mode_map':mode_map,'coefficient_key_table':hex(0x365f538),'coefficient_keys':list(map(hex,keys)),'source_u16':source,'settings_dat_base':hex(0x6602bc),'results':rows,'packing_boundary_cases':pack_cases}
(HERE/'Результаты.json').write_text(json.dumps(result,ensure_ascii=False,indent=2)+'\n',encoding='utf-8')
with (HERE/'Цвет.tsv').open('w',encoding='utf-8-sig',newline='') as f:
    w=csv.writer(f,delimiter='\t',lineterminator='\n');w.writerow(['native','index','gain','selector','a','b','d','c','field0','field1','field2','field3','writes'])
    for r in rows:w.writerow([r['native'],r['index'],r['gain'],r['selector'],*r['coefficients'],*r['packed_fields'],json.dumps(r['writes'],ensure_ascii=False)])
print(json.dumps(result,ensure_ascii=False,indent=2))
