"""Модельная трассировка X100VI; DAT только читается, аппаратные вызовы не исполняются."""
from pathlib import Path
import sys, importlib.util, hashlib, json, csv, struct, re
HERE=Path(__file__).resolve().parent
AN=HERE.parents[2]; ROOT=AN.parent
sys.path.insert(0,str(AN/'инструменты'))
def load(name,path):
    spec=importlib.util.spec_from_file_location(name,path); m=importlib.util.module_from_spec(spec); spec.loader.exec_module(m); return m
base=load('base',AN/'анализ_файла.py')
dist=load('dist',AN/'Распределение_систем_2026-11-01'/'исследовать_распределение.py')
from unicorn import Uc,UC_ARCH_ARM64,UC_MODE_ARM
from unicorn import arm64_const as R
SRC=ROOT/'Firmware на прочиеFuji'/'FPUPDATE.DAT'
raw=SRC.read_bytes(); sha=hashlib.sha256(raw).hexdigest(); assert sha=='0d48d2ae26ac7ebab9b0e4cac56324807ec1ea8ae30df06b0b9e79066dc0a14a'
data=raw.translate(base.TRANSLATION)
class Image(dist.Image):
    def __init__(self):
        self.raw=raw; self.data=data
        small=0xc02bc
        addr,size=struct.unpack_from('<QQ',data,small+8)
        self.blocks=[(addr,data[small:small+size]),(0x11c1000,base.unpack_fflz(data,0x9c02bc)),(0x2b8f000,base.unpack_fflz(data,0x10e02bc))]
        assert all(struct.unpack_from('<Q',b,8)[0]==a for a,b in self.blocks)
        self.cs=dist.Cs(dist.CS_ARCH_ARM64,dist.CS_MODE_ARM)
im=Image()
u=Uc(UC_ARCH_ARM64,UC_MODE_ARM); u.mem_map(0x1000,0x6000000-0x1000)
for a,b in im.blocks: u.mem_write(a,b)
u.mem_map(0x60000000,0x40000); u.mem_map(0x70000000,0x10000)
def reset():
    for i in range(31): u.reg_write(getattr(R,f'UC_ARM64_REG_X{i}'),0)
    u.reg_write(R.UC_ARM64_REG_SP,0x7000f000); u.mem_write(0x7000e000,bytes(0x2000))
def run(a,b,inputs={}):
    for i,v in inputs.items(): u.reg_write(getattr(R,f'UC_ARM64_REG_X{i}'),v)
    u.emu_start(a,b,timeout=500000,count=2000)
    assert u.reg_read(R.UC_ARM64_REG_PC)==b,hex(a)
def reg(i): return u.reg_read(getattr(R,f'UC_ARM64_REG_X{i}'))
def u32(a): return struct.unpack('<I',u.mem_read(a,4))[0]
def u64(a): return struct.unpack('<Q',u.mem_read(a,8))[0]
def desc(p): return {'id':u32(p),'name_pointer':u64(p+8),'priority':u32(p+16),'stack_bytes':u32(p+20),'entry':u64(p+24),'argument':u64(p+32)}
rows=[]; skipped=[]
for call,_ in im.calls({0x159a008}):
    r=dist.task_argument(im,call)
    if not r.get('name') or r.get('entry') is None:
        skipped.append({'call':hex(call),'reason':'name or entry unresolved','static':r}); continue
    ins=im.instructions(call-192,call)
    ptrs=[(a,v) for a,n,op,v in ins if op=='add' and re.fullmatch(r'x0, sp, #(?:0x[0-9a-f]+|\d+)',v)]
    starts=[]
    if ptrs:
        off=int(ptrs[-1][1].split('#')[1],0)
        starts=[a for a,n,op,v in ins if op=='str' and re.fullmatch(r'w\d+, \[sp, #(?:0x[0-9a-f]+|\d+)\]',v) and int(v.split('#')[1][:-1],0)==off]
    try:
        assert starts,'start not found'
        start=starts[-1]; prior=dist.task_argument(im,start)['register_values']
        supplied={int(k):v for k,v in prior.items() if v is not None and int(k)!=29}
        reset(); run(start,call,supplied); d=desc(reg(0))
        for field in ['id','name_pointer','priority','stack_bytes','entry']: assert d[field]==r[field],field
        assert im.string(d['name_pointer'])==r['name']
        source=0x60000000; tcb=0x60010000
        u.mem_write(source,struct.pack('<I4xQIIQQQ',d['id'],d['name_pointer'],d['priority'],d['stack_bytes'],d['entry'],d['argument'],0))
        reset(); run(0x159a0c0,0x159a0dc,{19:source}); lower=0x7000f040
        assert u64(lower+16)==d['entry'] and u64(lower+8)==d['argument']
        run(0x8dd7c,0x8ddb4,{19:lower,20:tcb}); assert u64(tcb+0x178)==d['entry'] and u64(tcb+0x198)==d['argument']
        u.mem_write(tcb+0x10,struct.pack('<Q',0x60020000))
        run(0x8de5c,0x8de90,{19:lower,20:tcb,21:tcb,22:tcb+0x15c}); assert reg(2)==0x970a4 and reg(3)==tcb
        run(0x970c8,0x970d0,{19:tcb}); assert reg(1)==d['entry'] and reg(0)==d['argument']
        rows.append({**d,'name':r['name'],'call':hex(call),'preparation_start':hex(start),'supplied_initial_registers':{str(k):hex(v) for k,v in supplied.items()},'evidence':'VM; константные входы из ограниченного статического анализа'})
    except Exception as e: skipped.append({'call':hex(call),'name':r['name'],'reason':repr(e)})
policy_base=0x1b627f8
policy_vm={}
for value in range(4):
    reset(); run(0x159a0a8,0x159a0c0,{2:value})
    policy_vm[str(value)]=reg(21)
assert policy_vm=={'0':1,'1':2,'2':4,'3':8}
for row in rows:
    policy=struct.unpack('<I',im.read(policy_base+(row['id']-1)*4,4))[0]
    row['default_policy']=policy
    row['default_allowed_mask']=policy_vm.get(str(policy))
# Два слова очереди: упаковка перед отправкой и распаковка перед непрямым вызовом.
reset(); run(0x96fcc,0x96fd4,{0:0x12345678,1:42}); packed=bytes(u.mem_read(0x7000f018,8))
assert struct.unpack('<II',packed)==(0x12345678,42)
reset(); u.mem_write(0x7000f038,packed); run(0x96fa4,0x96fac); assert reg(1)==0x12345678 and reg(0)==42
queue={'send_fragment':['0x96fcc','0x96fd4'],'receive_fragment':['0x96fa4','0x96fac'],'words_le':packed.hex(),'before_blr':{'x1':hex(reg(1)),'x0':reg(0)},'indirect_call_executed':False}
# Регистрация linux: стековый дескриптор, настоящий BL остановлен до выполнения.
reset(); run(0x30ef31c,0x30ef364); p=reg(2)
linux={'descriptor_pointer':hex(p),'id':reg(0),'arg1':reg(1),'entry':hex(u64(p)),'priority':u32(p+8),'stack_bytes':u64(p+16),'stack_pointer':hex(u64(p+24)),'argument':u64(p+32),'name_pointer':hex(u64(p+40)),'name':im.string(u64(p+40)),'call':'0x30ef364'}
assert linux['name']=='linux' and linux['id']==236
reset(); run(0x30ef374,0x30ef37c); linux['affinity_call_arguments']={'id':reg(0),'mask':reg(1)}
reset(); run(0x97bd0,0x97bdc,{21:4,19:0x60010000}); linux['affinity_exclusion_mask']=hex(reg(1))
reset(); run(0x33b0178,0x33b018c); boot={f'x{i}':hex(reg(i)) for i in range(5)}
# Подготовка канала ThreadX и Linux-обработчика socket из самой модели.
reset(); run(0x30f3270,0x30f3280,{20:0x60000000})
rpmsg={'threadx_call':'0x30f3280','threadx_function':'0x30f2c68','name_pointer':hex(reg(2)),'name':im.string(reg(2)),'arg0':hex(reg(0)),'arg1':reg(1)}
assert rpmsg['name']=='rpmsg-socket-api-channel'
arch=load('arch',AN/'Архитектура_2026-11-01'/'проверить_архитектуру.py')
ver=load('verify_boundary',AN/'Распределение_систем_2026-11-01'/'проверить_границу_систем.py')
fs,_=arch.gzip_at(data,0x499fe14); _,files,_=arch.cpio_entries(fs)
daemon=bytes(files['usr/bin/rpmsg-daemon']); sections,symbols=ver.elf_tables(daemon)
rel=sections['.rela.plt']; plt=sections['.plt']; socket_plt=None
for index,off in enumerate(range(rel[4],rel[4]+rel[5],24)):
    got,info,_=struct.unpack_from('<QQq',daemon,off)
    if symbols[info>>32]['name']=='socket': socket_plt=plt[3]+32+16*index
assert socket_plt==0x403160 and b'rpmsg-socket-api-channel' in daemon
h=struct.unpack_from('<16sHHIQQQIHHHHHH',daemon)
for j in range(h[10]):
    ph=struct.unpack_from('<IIQQQQQQ',daemon,h[5]+j*h[9])
    if ph[0]==1: u.mem_write(ph[3],daemon[ph[2]:ph[2]+ph[5]])
reset(); u.mem_write(0x60000008,struct.pack('<Q',0x60001000))
u.mem_write(0x6000100c,struct.pack('<3I',2,1,6)); u.reg_write(R.UC_ARM64_REG_X29,0x7000e000)
run(0x40c3a8,0x40c3c8,{23:0x60000000})
args=[reg(j) for j in range(3)]; assert args==[2,1,6]
w=struct.unpack_from('<I',daemon,sections['.text'][4]+0x40c3c8-sections['.text'][3])[0]
delta=w&0x3ffffff; delta=delta-(1<<26) if delta&(1<<25) else delta
assert w&0xfc000000==0x94000000 and 0x40c3c8+4*delta==socket_plt
rpmsg.update({'linux_daemon_sha256':hashlib.sha256(daemon).hexdigest(),'linux_fragment':'0x40c3a8..0x40c3c8','synthetic_fields':[2,1,6],'socket_arguments':args,'socket_plt':hex(socket_plt),'socket_called':False,'startup_texts':{p:bytes(files[p]).decode('utf8',errors='replace') for p in ['etc/inittab','etc/init.d/ffsys-init.sh','etc/init.d/rpmsg-daemon','etc/rpmsg-daemon.conf']}})
output={'source':str(SRC.relative_to(ROOT)),'sha256':sha,'mapping':[{'base':hex(a),'size':len(b),'sha256':hashlib.sha256(b).hexdigest()} for a,b in im.blocks],'task_registration':{'api':'0x159a008','static_call_sites':len(rows)+len(skipped),'vm_success':len(rows),'skipped':skipped,'records':rows,'bridge_fragments':['0x159a0c0..0x159a0dc','0x8dd7c..0x8ddb4','0x8de5c..0x8de90','0x970c8..0x970d0']},'dispatcher':queue,'linux':linux,'kernel_boot_registers':boot,'kernel_branch':'0x33b018c','limitations':['Константы перед началом некоторых фрагментов получены ограниченным статическим анализом; глобальная достижимость ветвей не установлена.','ThreadX, создание настоящих задач, Linux, SMC, MMIO и непрямые вызовы не запускаются.','Разрешённая маска CPU не доказывает фактическое исполнение на ядре.']}
output['task_registration']['policy_table']=hex(policy_base)
output['task_registration']['vm_policy_to_allowed_mask']=policy_vm
output['rpmsg']=rpmsg
assert hashlib.sha256(SRC.read_bytes()).hexdigest()==sha
(HERE/'Системы.json').write_text(json.dumps(output,ensure_ascii=False,indent=2)+'\n',encoding='utf-8')
with (HERE/'Задачи.tsv').open('w',encoding='utf-8-sig',newline='') as f:
    w=csv.DictWriter(f,fieldnames=['name','id','priority','stack_bytes','entry','argument','default_policy','default_allowed_mask','call','preparation_start'],delimiter='\t',extrasaction='ignore');w.writeheader();w.writerows(rows)
print(json.dumps({'tasks':len(rows),'skipped':len(skipped),'linux':linux,'boot':boot,'queue':queue},ensure_ascii=False))
