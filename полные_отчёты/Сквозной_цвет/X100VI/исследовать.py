"""X100VI: независимые модельные фрагменты, DAT только читается."""
from pathlib import Path
import hashlib, importlib.util, json, struct, sys

HERE = Path(__file__).resolve().parent
FW = HERE.parents[1]
ROOT = FW.parent
sys.path.insert(0, str(FW / 'инструменты'))
spec = importlib.util.spec_from_file_location('base', FW / 'анализ_файла.py')
base = importlib.util.module_from_spec(spec); spec.loader.exec_module(base)
from unicorn import Uc, UC_ARCH_ARM64, UC_MODE_ARM, UC_HOOK_MEM_WRITE
from unicorn.arm64_const import *
from capstone import Cs, CS_ARCH_ARM64, CS_MODE_LITTLE_ENDIAN

path = ROOT / 'Firmware на прочиеFuji' / 'FPUPDATE.DAT'
expected = '0d48d2ae26ac7ebab9b0e4cac56324807ec1ea8ae30df06b0b9e79066dc0a14a'
raw = path.read_bytes(); assert hashlib.sha256(raw).hexdigest() == expected
data = raw.translate(base.TRANSLATION)
a = base.unpack_fflz(data, 0x9c02bc); b = base.unpack_fflz(data, 0x10e02bc)
ab, bb = struct.unpack_from('<Q', a, 8)[0], struct.unpack_from('<Q', b, 8)[0]
assert (ab,bb)==(0x11c1000,0x2b8f000)
u = Uc(UC_ARCH_ARM64, UC_MODE_ARM)
u.mem_map(ab, ((bb+len(b)+4095)&-4096)-ab)
u.mem_write(ab,a); u.mem_write(bb,b)  # во взаимном перекрытии имеет приоритет второй блок
u.mem_map(0x40000,0x70000); u.mem_write(0x40000,data[0x7f2bc:0xef2bc])
assert data[0xde01c:0xde024] == bytes.fromhex('010000b9c0035fd6')
u.mem_map(0x27000000,0x400000); u.mem_write(0x27000000,data[0x6602bc:0xa002bc])
u.mem_write(0x211c1c8,struct.pack('<Q',0x27000000))
u.mem_map(0x60000000,0x40000); u.mem_map(0x70000000,0x10000); u.mem_map(0xff96c000,0x1000)
P,T,D,I,F,STOP = 0x60000000,0x60010000,0x60020000,0x60030000,0x60008000,0x70000000
regs = [UC_ARM64_REG_X0,UC_ARM64_REG_X1,UC_ARM64_REG_X2,UC_ARM64_REG_X3,UC_ARM64_REG_X4,UC_ARM64_REG_X5,UC_ARM64_REG_X6,UC_ARM64_REG_X7]
writes=[]
def onwrite(uc,access,address,size,value,user): writes.append({'address':hex(address),'size':size,'value':hex(value)})
u.hook_add(UC_HOOK_MEM_WRITE,onwrite,begin=0xff96c000,end=0xff96cfff)
def put(addr,val): u.mem_write(addr,struct.pack('<I',val&0xffffffff))
def get(addr): return struct.unpack('<I',u.mem_read(addr,4))[0]
def run(addr,until=STOP,args=()):
 for i,r in enumerate(regs): u.reg_write(r,args[i] if i<len(args) else 0)
 u.reg_write(UC_ARM64_REG_X30,STOP); u.reg_write(UC_ARM64_REG_SP,0x7000f000)
 u.emu_start(addr,until,count=200000)
 assert u.reg_read(UC_ARM64_REG_PC)==until, (hex(addr),hex(u.reg_read(UC_ARM64_REG_PC)),hex(until))
 return u.reg_read(UC_ARM64_REG_X0)&0xffffffff

def dictionary(name):
 p=b.find(name.encode('ascii')+b'\0'); assert p>=0
 pointer=struct.pack('<Q',bb+p); places=[]; n=0
 while True:
  n=b.find(pointer,n)
  if n<0: break
  if n%8==0: places.append(n)
  n+=1
 assert len(places)==1,(name,places)
 off=places[0]
 return {'name':name,'string':hex(bb+p),'record':hex(bb+off),'value':struct.unpack_from('<Q',b,off+8)[0]}

names=['EXTRA_DARK','SUPER_DARK','DARK','MID_DARK','STANDARD','MID_THIN','THIN','SUPER_THIN','EXTRA_THIN']
dicts=[dictionary('UI_FILM_SIM_CLASSIC_CHROME'),dictionary('UI_SETP_FILM_SIM'),dictionary('UI_SETP_STILLCOLOR')]+[dictionary('UI_STILLCOLOR_'+n) for n in names]
assert [x['value'] for x in dicts]==[14,1756,1793,*range(9)]
root=0x1c60a50
tables={}
for par in (1756,1793):
 address=struct.unpack_from('<Q',a,root-ab+par*8)[0]
 rows=[]
 for n in range(100):
  row=struct.unpack_from('<4I',a,address-ab+n*16)
  if row==(65535,)*4: break
  rows.append(list(row))
 else: raise ValueError('нет окончания таблицы')
 tables[str(par)]={'pointer':hex(address),'rows':rows}

def convert(par,v,src,dst):
 put(0x20b44c4,0); out=run(0x13c9930,args=(par,v,src,dst));return out,get(0x20b44c4)
color=[]
for ui in range(9):
 signed=struct.unpack('<i',struct.pack('<I',tables['1793']['rows'][ui][3]))[0]
 v,e=convert(1793,ui,0,3); assert e==0 and v==tables['1793']['rows'][ui][2]==ui
 fourth,e4=convert(1793,ui,0,4); reverse,er=convert(1793,fourth,4,3)
 assert e4==er==0 and fourth==(signed&0xffffffff) and reverse==v
 assert signed==40-ui*10
 color.append({'dictionary':names[ui],'ui_code':ui,'table_fourth_signed_tenths':signed,'executed_0_to_4':fourth,'executed_4_to_3':reverse,'mode_code':v,'error':e})

states=[]
for ui,prior in [(0,99),(14,99),(17,99),(18,99),(14,14)]:
 # Сравнение двух синтетических глобалов, переход к штатному конвертеру и setter.
 put(0x20b7178,ui);put(0x20b4ec0,prior);put(0x27f7a54,0x12345678)
 put(0x2897414,0);put(0x27f601c,0);put(0x20b44c4,0)
 stop=0x1411a54 if ui==prior else 0x1411fb4
 run(0x1411a3c,stop)
 state=get(0x27f7a54); error=get(0x20b44c4)
 if ui!=prior:
  expected_mode=tables['1756']['rows'][ui][2]; assert state==expected_mode and error==0
 else: assert state==0x12345678
 states.append({'ui':ui,'compared_global':prior,'entry':'0x1411a3c','stop':hex(stop),'state':state,'error':error})

cases=[]
for state in states[:4]:
 mode=state['state'];run(0x162a410,args=(F,mode));assert get(F+0xc0)==mode
 # Мост от кадра к следующим параметрам пока не известен: перенос выполняет экспериментатор.
 u.mem_write(P,bytes(0x1000));u.mem_write(T,bytes(0x1000))
 put(T+0x20,mode);u.reg_write(UC_ARM64_REG_X19,P);u.reg_write(UC_ARM64_REG_X20,T)
 run(0x31501c0,0x31501d4);code=get(P+0x130)
 assert get(P+0x12c)==1
 for c in color:
  u.mem_write(P,bytes(0x1000));u.mem_write(T,bytes(0x1000));u.mem_write(D,bytes(0x1000));u.mem_write(I,bytes(0x1000))
  run(0x314f388,args=(T,c['mode_code'],1,0)); index=get(T);assert index==8-c['mode_code']
  for off,val in [(0x12c,1),(0x130,code),(0x124,0x12),(0x128,0x12),(0x13c,index),(0x10c,8),(0x17c,2)]:put(P+off,val)
  run(0x313a1c0,args=(P,T));selector=u.mem_read(T,1)[0]
  run(0x313cef8,args=(P,D));coeff=list(struct.unpack('<4h',u.mem_read(D+0x1da,8)))
  run(0x145fb28,args=(D,I));fields=list(struct.unpack('<4H',u.mem_read(I+0x1ec,8)))
  writes.clear();run(0x145fbdc,args=(I,));observed=list(writes)
  assert fields==[v&0x1fff for v in coeff]
  assert [w['address'] for w in observed]==['0xff96c634','0xff96c638']
  cases.append({'ui_film':state['ui'],'mode':mode,'frame_c0':get(F+0xc0),'color_ui':c['ui_code'],'table_tenths':c['table_fourth_signed_tenths'],'native_color':c['mode_code'],'index':index,'processing_code':code,'selector':selector,'coefficients':coeff,'packed':fields,'writes':observed})
assert all(x['processing_code']==8 and x['selector']==6 for x in cases if x['ui_film']==14)
assert hashlib.sha256(path.read_bytes()).hexdigest()==expected
md=Cs(CS_ARCH_ARM64,CS_MODE_LITTLE_ENDIAN)
regions=[(0x1411a3c,0x1c),(0x1411fa0,0x18),(0x11f5a34,0x14),(0x13d2040,0x68),(0x162a408,0x10),(0x31501c0,0x18),(0x314f370,0x18),(0x314f388,0xb4)]
assembly=[]
for addr,size in regions:
 block,bs=(a,ab) if addr<bb else (b,bb)
 for i in md.disasm(block[addr-bs:addr-bs+size],addr): assembly.append({'pc':hex(i.address),'bytes':i.bytes.hex(),'instruction':i.mnemonic+' '+i.op_str})
result={'source':str(path.relative_to(ROOT)),'sha256_before_after':expected,'blocks':[{'dat':'0x9c02bc','base':hex(ab),'size':hex(len(a)),'sha256':hashlib.sha256(a).hexdigest()},{'dat':'0x10e02bc','base':hex(bb),'size':hex(len(b)),'sha256':hashlib.sha256(b).hexdigest()}],'overlap':{'start':hex(bb),'end_exclusive':hex(ab+len(a)),'priority':'second block'},'dictionary':dicts,'table_root':hex(root),'tables':tables,'color_conversion':color,'state_execution':states,'execution_cases':cases,'disassembly':assembly,'limitations':['synthetic globals and structures','manual links state to frame and frame to processing','not physical registers or a camera']}
(HERE/'Результаты.json').write_text(json.dumps(result,ensure_ascii=False,indent=2)+'\n',encoding='utf-8')
print(json.dumps({'states':states,'color':color,'case_count':len(cases)},ensure_ascii=False,indent=2))
