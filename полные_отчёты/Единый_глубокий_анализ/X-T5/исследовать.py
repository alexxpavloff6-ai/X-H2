"""X-T5 4.31: модельные инструкции ARM64 в изолированном Unicorn; DAT только читается."""
from pathlib import Path
import sys, importlib.util, hashlib, json, struct, csv, re

HERE=Path(__file__).resolve().parent
ROOT=HERE.parents[1]
sys.path.insert(0,str(ROOT/'инструменты'))
from capstone import Cs, CS_ARCH_ARM64, CS_MODE_ARM
from unicorn import Uc, UC_ARCH_ARM64, UC_MODE_ARM, UC_HOOK_MEM_WRITE, UC_HOOK_CODE
from unicorn import arm64_const as R
def load(name,path):
    spec=importlib.util.spec_from_file_location(name,path); m=importlib.util.module_from_spec(spec); spec.loader.exec_module(m); return m
base=load('base',ROOT/'анализ_файла.py')
dist=load('dist',ROOT/'Распределение_систем_2026-11-01/исследовать_распределение.py')
source=ROOT.parent/'Firmware на прочиеFuji/FWUP0030.DAT'
raw=source.read_bytes(); sha=hashlib.sha256(raw).hexdigest(); data=raw.translate(base.TRANSLATION)
a=base.unpack_fflz(data,0x300274); b=base.unpack_fflz(data,0x820274)
image=dist.Image.__new__(dist.Image); image.raw=raw; image.data=data
image.blocks=[(0x40000,data[0x60274:0x7e5b4]),(0x1101000,a),(0x28eb000,b)]
image.cs=Cs(CS_ARCH_ARM64,CS_MODE_ARM)
uc=Uc(UC_ARCH_ARM64,UC_MODE_ARM)
for addr,block in image.blocks:
    size=(len(block)+4095)&~4095; uc.mem_map(addr,size); uc.mem_write(addr,block)
# Все записи глобальных переменных и устройства — только в искусственной памяти.
aend=0x1101000+((len(a)+4095)&~4095); bend=0x28eb000+((len(b)+4095)&~4095)
uc.mem_map(aend,0x28eb000-aend); uc.mem_map(bend,0x6000000-bend)
uc.mem_map(0x27008000,0x100000); uc.mem_write(0x27008000,data[0xc0274:0xc0274+0xc6c00]); uc.mem_write(0x2066d90,struct.pack('<Q',0x27008000))
uc.mem_map(0x60000000,0x40000); uc.mem_map(0x70000000,0x10000); uc.mem_map(0xff96c000,0x4000)
def reg(n): return uc.reg_read(getattr(R,'UC_ARM64_REG_X'+str(n)))
def reset():
    for j in range(31): uc.reg_write(getattr(R,'UC_ARM64_REG_X'+str(j)),0)
    uc.reg_write(R.UC_ARM64_REG_SP,0x7000f000); uc.reg_write(R.UC_ARM64_REG_X30,0x70000000)
    uc.mem_write(0x7000e000,bytes(0x2000))
def run(start,end=0x70000000,inputs=None,count=200000):
    for n,v in (inputs or {}).items(): uc.reg_write(getattr(R,'UC_ARM64_REG_X'+str(n)),v)
    uc.emu_start(start,end,timeout=1000000,count=count)
    if uc.reg_read(R.UC_ARM64_REG_PC)!=end: raise RuntimeError('PC '+hex(uc.reg_read(R.UC_ARM64_REG_PC)))
def u32(p): return struct.unpack('<I',uc.mem_read(p,4))[0]
def u64(p): return struct.unpack('<Q',uc.mem_read(p,8))[0]
def word(p,v): uc.mem_write(p,struct.pack('<I',v))
def desc(p): return dict(id=u32(p),name_pointer=u64(p+8),priority=u32(p+16),stack_bytes=u32(p+20),entry=u64(p+24),argument=u64(p+32))
results={'source':str(source),'source_sha256':sha,'blocks':[{'base':hex(k),'length':len(v),'sha256':hashlib.sha256(v).hexdigest()} for k,v in image.blocks], 'address_note':'Базы FFLZ читаются из заголовков; low-модуль условно 0x40000; абсолютное размещение на камере не доказано.'}
# Статический поиск BL включает неисполняемые данные; значения кандидатов подтверждаются отдельным VM-фрагментом.
candidates=[]; verified=[]; skipped=[]
for call,target in image.calls({0x14c5df4}):
    try:
        r=dist.task_argument(image,call)
        if not r.get('name') or r.get('entry') is None: continue
        candidates.append(r)
        ins=image.instructions(call-192,call)
        ptrs=[(z,o) for z,n,op,o in ins if op=='add' and re.fullmatch(r'x0, sp, #(?:0x[0-9a-f]+|\d+)',o)]
        if not ptrs: raise ValueError('адрес описателя не восстановлен')
        off=int(ptrs[-1][1].split('#')[1],0)
        starts=[z for z,n,op,o in ins if op=='str' and re.fullmatch(r'w\d+, \[sp, #(?:0x[0-9a-f]+|\d+)\]',o) and int(o.split('#')[1][:-1],0)==off]
        if not starts: raise ValueError('начало заполнения не найдено')
        start=starts[-1]; prior=dist.task_argument(image,start)['register_values']; supplied={int(k):v for k,v in prior.items() if v is not None and int(k)!=29}
        reset(); run(start,call,supplied); rec=desc(reg(0))
        for k in ('id','name_pointer','priority','stack_bytes','entry'):
            if rec[k]!=r[k]: raise ValueError('расхождение '+k)
        rec.update(name=r['name'],call=hex(call),preparation_start=hex(start),initial_registers={str(k):hex(v) for k,v in supplied.items()})
        # Реальное преобразование описателя в формат системного кода и подготовка TCB.
        sourcep=0x60000000; tcb=0x60010000; buf=bytearray(48)
        for name,off,fmt in [('id',0,'I'),('name_pointer',8,'Q'),('priority',16,'I'),('stack_bytes',20,'I'),('entry',24,'Q'),('argument',32,'Q')]: struct.pack_into('<'+fmt,buf,off,rec[name])
        reset(); uc.mem_write(sourcep,bytes(buf)); run(0x14c5eac,0x14c5ec8,{19:sourcep}); lower=0x7000f040
        if u64(lower+16)!=rec['entry'] or u64(lower+8)!=rec['argument']: raise ValueError('описатель bridge')
        run(0x4cd74,0x4cdac,{19:lower,20:tcb})
        if u64(tcb+0x178)!=rec['entry'] or u64(tcb+0x170)!=rec['argument']: raise ValueError('TCB bridge')
        uc.mem_write(tcb+0x10,struct.pack('<Q',0x60020000)); run(0x4ce54,0x4ce88,{19:lower,20:tcb,21:tcb,22:tcb+0x15c})
        rec['threadx_common_entry']=hex(reg(2)); rec['threadx_argument']=hex(reg(3))
        run(0x560c0,0x560c8,{19:tcb}); rec['bridge_entry']=hex(reg(1)); rec['bridge_argument']=hex(reg(0))
        verified.append(rec)
    except Exception as e: skipped.append({'call':hex(call),'reason':str(e)})
results['task_registration']={'api':hex(0x14c5df4),'static_candidates':len(candidates),'vm_records':verified,'skipped':skipped,'limitations':'Ветви до фрагментов не исполнялись; создания и расписания потоков нет; группы фабрик не исчерпаны.'}
# Описатель linux и affinity; затем отдельный безопасный фрагмент без перехода в ядро.
reset(); run(0x2e186d0,0x2e18718); p=reg(2)
linux={'id':reg(0),'mode':reg(1),'entry':hex(u64(p)),'priority':u32(p+8),'stack':u64(p+16),'argument':hex(u64(p+32)),'name_pointer':hex(u64(p+40)),'name':image.string(u64(p+40))}
reset(); run(0x2e18728,0x2e18730); linux['affinity_call_id']=reg(0); linux['affinity_mask']=reg(1)
run(0x56bc8,0x56bd4,{21:4,19:0x60010000}); linux['exclusion_mask']=hex(reg(1))
reset(); run(0x30d6178,0x30d618c); linux['boot_registers']={f'x{i}':hex(reg(i)) for i in range(5)}
linux.update(descriptor_fragment='0x2e186d0..0x2e18718',affinity_fragment='0x2e18728..0x2e18730',boot_fragment='0x30d6178..0x30d618c',limitation='Остановка до BLR; ядро не запускалось. Маска affinity вызвана отдельно, расписание не измерено.')
results['linux_boot_rpmsg']=linux
# Отдельно фрагменты формируют данные запросов, без вызова транспорта или записи носителей.
param=bytes.fromhex('4433221188776655ccbbaa9900ffeedd'); uc.mem_write(0x60000000,param)
updates=[]
for name,start,end in [('INIT',0x2c7b258,0x2c7b290),('START',0x2c7b29c,0x2c7b2b8),('WRITE',0x2c7b2dc,0x2c7b2f0),('DEINIT',0x2c7b320,0x2c7b334)]:
    reset(); run(start,end,{0:0x60000000,19:0x60000000}); updates.append({'stage':name,'entry':hex(start),'stop_before_call':hex(end),'command':hex(reg(0)),'length':reg(1),'payload':bytes(uc.mem_read(reg(2),reg(1))).hex()})
results['update']={'vm':updates,'packager':hex(0x2c7b210),'handlers':{'INIT':{'entry':'0x298c500','call':'0x298c5e0'},'START':{'entry':'0x298c65c','call':'0x298c698'},'WRITE':{'entry':'0x298c6ec','call':'0x298c778'},'DEINIT':{'entry':'0x298c454','call':'0x298c498'}},'limitations':'Связи обработчиков и помощников разобраны статически. Фрагменты WRITE/DEINIT после служебного вызова; транспорт и запись не выполнялись.'}
# Модельная таблица, выбор режима, шкала и расчёт коэффициентов из оригинальных инструкций.
p=0x60000000; q=0x60010000; color=[]
for name,mode in [('STANDARD',0),('CLASSIC_CHROME',13),('ETERNA',18),('REALA',22)]:
    uc.mem_write(p,bytes(0x1000)); reset(); run(0x2e73f2c,inputs={0:p,1:mode}); col=u32(p)
    uc.mem_write(p,bytes(0x1000)); uc.mem_write(q,bytes(0x1000))
    for off,v in [(0x12c,1),(0x130,col),(0x124,0x12),(0x128,0x12),(0x13c,4),(0x10c,8),(0x17c,2),(0x180,0)]: word(p+off,v)
    reset(); run(0x2e5f410,inputs={0:p,1:q}); selector=bytes(uc.mem_read(q,1))[0]
    uc.mem_write(q,bytes(0x1000)); reset(); run(0x2e5f7dc,inputs={0:p,1:q})
    color.append({'name':name,'mode':mode,'color_mode':col,'selector':selector,'coefficients_3c':list(struct.unpack('<4h',uc.mem_read(q+0x3c,8)))})
results['color_chain']={'runs':color,'mode_function':'0x2e73f2c','selector_function':'0x2e5f410','coefficient_function':'0x2e5f7dc','template_base':'0x27008000','template_dat_offset':'0xc0274','key_table':'0x3364638','inputs':'Синтетический контекст как в эксперименте X-H2; физические настройки не прочитаны.'}
# Подлинная упаковка, затем запись в виртуальные MMIO по модельной таблице дескрипторов.
pack=0x1101000+0x2737a0
uc.mem_write(p+0x1da,struct.pack('<4h',885,-10,859,-12)); uc.mem_write(q+0x1ec,struct.pack('<4H',*([0xa000]*4))); reset(); run(pack,inputs={0:p,1:q})
results['color_chain']['packing']={'function':hex(pack),'input':[885,-10,859,-12],'upper_bits':'0xa000','output':list(struct.unpack('<4H',uc.mem_read(q+0x1ec,8)))}
# Условный адрес системного модуля; очередь и колбэк сами не запускаются.
reset(); run(0x55fbc,0x55fdc,{0:0x12345678,1:42})
queue=reg(0); message=bytes(uc.mem_read(reg(1),8)); send_arg=reg(2)
reset(); uc.mem_write(0x7000f038,struct.pack('<2I',0x12345678,42)); run(0x55f98,0x55fa4,{0:0})
results['dispatcher']={'status':'выполнено в VM до системного вызова и BLR','send_fragment':'0x55fbc..0x55fdc','queue_pointer':hex(queue),'message':message.hex(),'third_argument':send_arg,'receive_fragment':'0x55f98..0x55fa4','callback':hex(reg(1)),'argument':reg(0),'limitations':'Условная база 0x40000; реальная очередь и колбэк не выполнялись.'}
# Подлинный выбор внутреннего представления по коду UI.
reset(); word(0x20007ec,0); run(0x12e48b0,inputs={0:1699,1:14,2:0,3:3})
results['color_chain']['ui_conversion']={'function':'0x12e48b0','inputs':[1699,14,0,3],'output':reg(0),'error_flag':u32(0x20007ec),'table_record':list(struct.unpack_from('<4I',a,0x1759c70-0x1101000+14*16))}
# Сквозная проверка сборщика, упаковщика и MMIO на девяти значениях Color.
writes=[]
def capture(uc,access,address,size,value,user):
    writes.append({'address':hex(address),'size':size,'value':hex(value),'pc':hex(uc.reg_read(R.UC_ARM64_REG_PC))})
hook=uc.hook_add(UC_HOOK_MEM_WRITE,capture,begin=0xff96c000,end=0xff96ffff)
general=0x60010000; registers=0x60020000; sequence=[]
for index in range(9):
    uc.mem_write(p,bytes(0x1000)); uc.mem_write(general,bytes(0x2000)); uc.mem_write(registers,bytes(0x1000))
    for off,v in [(0x12c,1),(0x130,8),(0x124,18),(0x128,18),(0x13c,index),(0x10c,8),(0x17c,2)]: word(p+off,v)
    reset(); run(0x2e57910,0x2e57928,{19:p,21:general+0x96c})
    coeff=list(struct.unpack('<4h',uc.mem_read(general+0xb46,8)))
    reset(); run(0x2e57f0c,inputs={0:general,1:0x80,2:registers})
    packed=list(struct.unpack('<4H',uc.mem_read(registers+0x1ec,8)))
    writes.clear(); reset(); run(0x2e57f38,inputs={0:0x80,1:registers})
    selected=[w for w in writes if w['address'] in ('0xff96c634','0xff96c638')]
    sequence.append({'color_index':index,'gain':data[0xc0274+0xaf50+index],'coefficients':coeff,'packed':packed,'mmio_writes':selected})
    assert len(selected)==2
writes.clear(); reset(); run(0x2e57f38,inputs={0:0,1:registers})
assert not any(w['address'] in ('0xff96c634','0xff96c638') for w in writes)
uc.hook_del(hook)
results['color_chain']['register_chain']={'assembler':'0x2e57910..0x2e57928','packer':'0x2e57f0c','transmitter':'0x2e57f38','descriptor_table':'0x18dcb38','runs':sequence,'zero_mask_control':'нет записей в выбранную пару','limitations':'MMIO — отображенная искусственная RAM, не аппарат камеры.'}
# Задачи с AF-подобными именами: исполнение фактических инструкций до вызова ожидания,
# а затем отдельно подготовка следующего вызова с искусственным сообщением.
af=[]
for name,start,wait_call,next_start,next_call,context in [('paf_sub0',0x3076740,0x3076774,0x3076778,0x3076780,0x4ba0ec8),('paf_sub1',0x3076788,0x30767bc,0x30767c0,0x30767c8,0x4961748)]:
    reset(); run(start,wait_call); waiting=[reg(j) for j in range(3)]
    uc.mem_write(waiting[1],struct.pack('<H',0x17d5))
    run(next_start,next_call)
    af.append({'task':name,'entry':hex(start),'wait_call':hex(wait_call),'wait_target':'0x14c71b8','wait_arguments':[hex(x) for x in waiting],'injected_message':'0x17d5','next_call':hex(next_call),'target':'0x3075c40','arguments':[hex(reg(0)),hex(reg(1))],'context_expected':hex(context)})
results['autofocus']={'status':'фрагменты выполнены в VM','tasks':af,'limitations':'Имя PAF не раскрывает алгоритм; сообщение искусственное, служба ожидания и вызываемая функция не исполнялись; движение объектива и достижимость сообщения не установлены.'}
# Конфигурация и ARM64 ELF из модели, без запуска демона целиком.
arch=load('arch',ROOT/'Архитектура_2026-11-01/проверить_архитектуру.py')
fs,used=arch.gzip_at(data,0x42dfdcc); _,files,_=arch.cpio_entries(fs)
daemon=bytes(files['usr/bin/rpmsg-daemon']); h=struct.unpack_from('<16sHHIQQQIHHHHHH',daemon)
segments=[struct.unpack_from('<IIQQQQQQ',daemon,h[5]+j*h[9]) for j in range(h[10])]
segments=[s for s in segments if s[0]==1]
lo=min(s[3]&~4095 for s in segments); hi=max((s[3]+s[6]+4095)&~4095 for s in segments)
uc.mem_map(lo,hi-lo)
for s in segments: uc.mem_write(s[3],daemon[s[2]:s[2]+s[5]])
reset(); uc.mem_write(0x60000008,struct.pack('<Q',0x60001000)); uc.mem_write(0x6000100c,struct.pack('<3I',2,1,6))
uc.reg_write(R.UC_ARM64_REG_X29,0x7000e000); run(0x40c3a8,0x40c3c8,{23:0x60000000})
linux['rpmsg']={'channel_address':hex(0x28eb000+b.find(b'rpmsg-socket-api-channel')),'channel':'rpmsg-socket-api-channel','daemon_sha256':hashlib.sha256(daemon).hexdigest(),'daemon_channel_offset':hex(daemon.find(b'rpmsg-socket-api-channel')),'socket_fragment':'0x40c3a8..0x40c3c8','request_fields':[2,1,6],'socket_arguments':[reg(j) for j in range(3)],'config':bytes(files['etc/rpmsg-daemon.conf']).decode('utf-8',errors='replace'),'limitations':'Аргументы синтетические; libc socket и RPmsg не исполнялись.'}
reset(); run(0x2e1c698,0x2e1c6a8,{20:0x60000000})
linux['rpmsg']['main_setup']={'fragment':'0x2e1c698..0x2e1c6a8','call_target':'0x2e1c090','arguments':[hex(reg(j)) for j in range(3)],'first_argument':'синтетический указатель'}
linux['bootargs']=[x.decode('ascii',errors='replace') for x in data[0x3c40274:0x3c42f15].split(b'\0') if b'maxcpus=' in x]
for rec in verified:
    if 1<=rec['id']<=213:
        policy=struct.unpack_from('<I',a,0x1ab50a0-0x1101000+(rec['id']-1)*4)[0]
        reset(); word(0x60030000,rec['id']); run(0x14c5e80,0x14c5eb0,{19:0x60030000})
        rec['default_core_policy']=policy
        rec['default_allowed_mask']=hex(reg(21))
        assert reg(21)==(1<<policy if policy<4 else 0)
results['task_registration']['policy_table']='0x1ab50a0; обращение по ID-1 и преобразование в маску выполнены в VM на 0x14c5e80..0x14c5eb0; значение >=4 означает особый путь с нулевой маской.'
results['task_registration']['policy_limit']='Политика при регистрации, не измеренное расписание; настройки могут изменяться.'
assert hashlib.sha256(source.read_bytes()).hexdigest()==sha
results['source_unchanged']=True
(HERE/'результаты.json').write_text(json.dumps(results,ensure_ascii=False,indent=2)+'\n',encoding='utf-8')
with (HERE/'задачи.tsv').open('w',encoding='utf-8-sig',newline='') as f:
    w=csv.DictWriter(f,fieldnames=['name','id','priority','stack_bytes','entry','argument','call','preparation_start','threadx_common_entry','bridge_entry','default_core_policy','default_allowed_mask'],delimiter='\t',extrasaction='ignore'); w.writeheader(); w.writerows(verified)
print(json.dumps({'tasks':len(verified),'skipped':len(skipped),'linux':linux,'update':updates,'color':color},ensure_ascii=False,indent=2))
