"""X-H2S 7.30: фрагменты оригинального ARM64 в искусственной памяти Unicorn.
DAT только читается. Запись результатов исключительно рядом с этим скриптом.
"""
from pathlib import Path
import sys, importlib.util, hashlib, struct, re, json, csv

HERE = Path(__file__).resolve().parent
ROOT = HERE.parents[1]
PROJECT = ROOT.parent
SOURCE = PROJECT/'Firmware на прочиеFuji/FWUP0027.DAT'
sys.path.insert(0, str(ROOT/'инструменты'))
def load(name, path):
    spec = importlib.util.spec_from_file_location(name, path)
    module = importlib.util.module_from_spec(spec); spec.loader.exec_module(module); return module
base = load('base', ROOT/'анализ_файла.py')
dist = load('dist', ROOT/'Распределение_систем_2026-11-01/исследовать_распределение.py')
arch = load('arch', ROOT/'Архитектура_2026-11-01/проверить_архитектуру.py')
from capstone import Cs, CS_ARCH_ARM64, CS_MODE_ARM
from unicorn import Uc, UC_ARCH_ARM64, UC_MODE_ARM, UC_HOOK_MEM_WRITE
from unicorn import arm64_const as reg

class Image(dist.Image):
    def __init__(self):
        self.raw = SOURCE.read_bytes(); self.data = self.raw.translate(base.TRANSLATION)
        self.blocks = [(0x40000, self.data[0x60274:0x60274+0x1e340])]
        for offset in (0x300274, 0x840274):
            block = base.unpack_fflz(self.data, offset)
            self.blocks.append((struct.unpack_from('<Q', block, 8)[0], block))
        self.cs = Cs(CS_ARCH_ARM64, CS_MODE_ARM)

class VM:
    def __init__(self, image):
        self.u = Uc(UC_ARCH_ARM64, UC_MODE_ARM)
        self.u.mem_map(0x40000, 0x5fc0000)
        for address, block in image.blocks: self.u.mem_write(address, block)
        self.u.mem_map(0x27008000, 0x800000)
        self.u.mem_write(0x27008000, image.data[0xc0274:0xc0274+0xc6c00])
        self.u.mem_write(0x23dbc30, struct.pack('<Q', 0x27008000))
        self.u.mem_map(0x60000000, 0x40000); self.u.mem_map(0x70000000, 0x10000)
        self.count = 0
    def run(self, start, stop, inputs=None):
        for j in range(31): self.u.reg_write(getattr(reg, 'UC_ARM64_REG_X'+str(j)), 0)
        self.u.reg_write(reg.UC_ARM64_REG_SP, 0x7000f000)
        self.u.reg_write(reg.UC_ARM64_REG_X30, 0x70000000)
        self.u.mem_write(0x7000d000, bytes(0x3000))
        for j,v in (inputs or {}).items(): self.u.reg_write(getattr(reg, 'UC_ARM64_REG_X'+str(j)), v)
        self.u.emu_start(start, stop, count=200000, timeout=1000000)
        if self.u.reg_read(reg.UC_ARM64_REG_PC) != stop: raise ValueError('не достигнута граница '+hex(start))
        self.count += 1
    def x(self,n): return self.u.reg_read(getattr(reg, 'UC_ARM64_REG_X'+str(n)))
    def u32(self,p): return struct.unpack('<I',self.u.mem_read(p,4))[0]
    def u64(self,p): return struct.unpack('<Q',self.u.mem_read(p,8))[0]
    def put32(self,p,v): self.u.mem_write(p,struct.pack('<I',v))

def descriptor(vm,p):
    return {'id':vm.u32(p),'name_pointer':vm.u64(p+8),'priority':vm.u32(p+16),
            'stack_bytes':vm.u32(p+20),'entry':vm.u64(p+24),'argument':vm.u64(p+32)}

def main():
    im=Image(); sha=hashlib.sha256(im.raw).hexdigest()
    assert sha=='87c566c1ff6343e4c7463a4ef968183f41d1f24cc63d610433d3a387b13f731b'
    v=VM(im); candidates=[]; verified=[]; skipped=[]
    for call,_ in im.calls({0x17edb98}):
        row=dist.task_argument(im,call); candidates.append(row)
        if not row.get('name') or row.get('entry') is None: continue
        ins=im.instructions(call-192,call)
        ptr=[(a,s) for a,n,op,s in ins if op=='add' and re.fullmatch(r'x0, sp, #(?:0x[0-9a-f]+|\d+)',s)]
        starts=[]
        if ptr:
            offset=int(ptr[-1][1].split('#')[1],0)
            starts=[a for a,n,op,s in ins if op=='str' and re.fullmatch(r'w\d+, \[sp, #(?:0x[0-9a-f]+|\d+)\]',s) and int(s.split('#')[1][:-1],0)==offset]
        try:
            if not starts: raise ValueError('нет начала подготовки')
            start=starts[-1]; prior=dist.task_argument(im,start)['register_values']
            supplied={int(k):val for k,val in prior.items() if val is not None and int(k)!=29}
            v.run(start,call,supplied); rec=descriptor(v,v.x(0))
            for k in ['id','name_pointer','priority','stack_bytes','entry']:
                if rec[k]!=row[k]: raise ValueError('несовпадение '+k)
            if im.string(rec['name_pointer'])!=row['name']: raise ValueError('имя')
            verified.append({**rec,'name':row['name'],'call':hex(call),'start':hex(start),'input_registers':supplied,'method':'VM: локальная подготовка; регистры выведены статически'})
        except Exception as ex: skipped.append({'name':row.get('name'),'call':hex(call),'reason':str(ex)})
    groups=[]
    for target,start,end,registers in [(0x318a314,0x318a36c,0x318a398,(19,21,20)),(0x31ae688,0x31ae6d0,0x31ae6fc,(21,20,19))]:
        for call,_ in im.calls({target}):
            args=dist.task_argument(im,call)['argument_registers']; values=[args['x0'],args['x1'],args['x2']]
            name=im.string(values[1])
            if None in values or not name: continue
            try:
                v.run(start,end,dict(zip(registers,values))); rec=descriptor(v,v.x(0))
                if rec['id']!=values[0] or rec['name_pointer']!=values[1]: raise ValueError('descriptor mismatch')
                groups.append({**rec,'name':name,'call':hex(call),'factory':hex(target),'start':hex(start),'method':'VM: конец фабрики; константы вызова статически'})
            except Exception as ex: skipped.append({'name':name,'call':hex(call),'reason':str(ex)})
    # Сходные с нижней системой оригинальные фрагменты проверяются на одном реальном описателе.
    sample=verified[0]; src=0x60000000; tcb=0x60010000
    buf=bytearray(48)
    for k,off,fmt in [('id',0,'I'),('name_pointer',8,'Q'),('priority',16,'I'),('stack_bytes',20,'I'),('entry',24,'Q'),('argument',32,'Q')]: struct.pack_into('<'+fmt,buf,off,sample[k])
    v.u.mem_write(src,bytes(buf)); v.run(0x17edc50,0x17edc6c,{19:src}); lower=0x7000f040
    lower_result={'entry':v.u64(lower+16),'argument':v.u64(lower+8)}
    # run() очищает стек, поэтому переносим фактически сформированный нижний объект отдельно.
    lower_bytes=bytes(v.u.mem_read(lower,48)); v.u.mem_write(0x60020000,lower_bytes)
    v.run(0x4cd74,0x4cdac,{19:0x60020000,20:tcb})
    bridge={'source_task':sample['name'],'fragment_upper':'0x17edc50..0x17edc6c','fragment_tcb':'0x4cd74..0x4cdac','lower':lower_result,'tcb_entry':v.u64(tcb+0x178),'tcb_argument':v.u64(tcb+0x170)}
    assert bridge['tcb_entry']==sample['entry'] and bridge['tcb_argument']==sample['argument']
    v.run(0x55fbc,0x55fdc,{0:0x12345678,1:42}); msg=v.x(1)
    dispatch={'send_fragment':'0x55fbc..0x55fdc','queue':hex(v.x(0)),'message':list(struct.unpack('<2I',v.u.mem_read(msg,8))),'wait':v.x(2)}
    # Этот фрагмент получает содержимое стека, поэтому выполнить после очистки вручную.
    v.u.reg_write(reg.UC_ARM64_REG_SP,0x7000f000);v.u.reg_write(reg.UC_ARM64_REG_X0,0);v.u.mem_write(0x7000f038,struct.pack('<2I',0x12345678,42));v.u.emu_start(0x55f98,0x55fa4,count=100)
    dispatch.update({'receive_fragment':'0x55f98..0x55fa4','prepared_argument':v.x(0),'prepared_callback':hex(v.x(1))});v.count+=1
    v.run(0x31f24c0,0x31f2508); lp=v.x(2)
    linux={'registration_fragment':'0x31f24c0..0x31f2508','id':v.x(0),'entry':hex(v.u64(lp)),'priority':v.u32(lp+8),'stack_bytes':v.u64(lp+16),'argument':v.u64(lp+32),'name':im.string(v.u64(lp+40)), 'affinity_static_instruction':'0x31f2518 mov w1, #4; 0x31f251c mov w0, #0xc0; 0x31f2520 bl', 'entry_static': '0x31f2420','monitor_call_static':'0x31f2470 -> 0x34a92fc'}
    v.run(0x34a9178,0x34a918c);linux['boot_fragment']='0x34a9178..0x34a918c';linux['boot_registers']={f'x{i}':hex(v.x(i)) for i in range(5)}
    v.run(0x56bc8,0x56bd4,{21:4,19:0x60020000})
    linux['affinity_vm']={'fragment':'0x56bc8..0x56bd4','allowed_mask':'0x4','result_exclusion_mask':hex(v.x(1))}
    fs,_=arch.gzip_at(im.data,0x42dfdcc);_,files,_=arch.cpio_entries(fs)
    linux['cpio_sha256']=hashlib.sha256(fs).hexdigest()
    linux['rpmsg_conf']=bytes(files['etc/rpmsg-daemon.conf']).decode();linux['inittab'] = bytes(files['etc/inittab']).decode()
    channel_offset=im.blocks[2][1].find(b'rpmsg-socket-api-channel')
    assert channel_offset>=0
    linux['channel_rtos_address']=hex(0x2cca000+channel_offset)
    linux['channel_in_daemon']=b'rpmsg-socket-api-channel' in bytes(files['usr/bin/rpmsg-daemon'])
    # ELF-загрузочные сегменты того же собственного CPIO; импорт socket не исполняется.
    daemon=bytes(files['usr/bin/rpmsg-daemon'])
    elf=struct.unpack_from('<16sHHIQQQIHHHHHH',daemon)
    segments=[struct.unpack_from('<IIQQQQQQ',daemon,elf[5]+j*elf[9]) for j in range(elf[10])]
    loads=[s for s in segments if s[0]==1]
    assert all(0x40000 <= s[3] and s[3]+s[6] <= 0x6000000 for s in loads)
    for s in loads: v.u.mem_write(s[3],daemon[s[2]:s[2]+s[5]])
    v.u.mem_write(0x60000008,struct.pack('<Q',0x60001000))
    v.u.mem_write(0x6000100c,struct.pack('<3I',2,1,6))
    v.run(0x40c3a8,0x40c3c8,{23:0x60000000,29:0x7000e000})
    linux['socket_vm']={'fragment':'0x40c3a8..0x40c3c8','request_values':[2,1,6],
                        'arguments':[v.x(0),v.x(1),v.x(2)],'call_static':'0x40c3c8 -> socket@plt 0x403160',
                        'socket_not_called':True}
    v.run(0x1604da0,0x70000000,{0:1677,1:14,2:0,3:3})
    ui={'function':'0x1604da0','inputs':[1677,14,0,3],'result':v.x(0),'error_flag_address':'0x236b408','error_flag':v.u32(0x236b408)}
    label_pointer,label_value=struct.unpack('<QI',im.read(0x3538f78,12))
    ui['dictionary_record']='0x3538f78';ui['dictionary_value']=label_value
    ui['dictionary_string_address']=hex(label_pointer);ui['dictionary_name']=im.string(label_pointer)
    ui['conversion_table_record_address']='0x1a784c8'
    ui['conversion_table_record']=list(struct.unpack('<4I',im.read(0x1a784c8,16)))
    assert ui['dictionary_name']=='UI_FILM_SIM_CLASSIC_CHROME' and label_value==14
    assert ui['result']==13 and ui['error_flag']==0
    # Условные синтетические состояния, не снимки реальной камеры.
    p=0x60000000;o=0x60010000; color=[]
    for mode in [0,1,3,11,12,13,18,19,20,21,22]:
        v.u.mem_write(p,bytes(4096));v.run(0x324f9a8,0x70000000,{0:p,1:mode});mapped=v.u32(p)
        v.u.mem_write(p,bytes(4096));v.u.mem_write(o,bytes(4096))
        for off,val in [(0x12c,1),(0x130,mapped),(0x124,0x12),(0x128,0x12),(0x13c,4),(0x10c,8),(0x17c,2),(0x180,0)]:v.put32(p+off,val)
        v.run(0x323b004,0x70000000,{0:p,1:o});selector=v.u.mem_read(o,1)[0]
        v.u.mem_write(o,bytes(4096));v.run(0x323b400,0x70000000,{0:p,1:o})
        coeff=list(struct.unpack('<4h',v.u.mem_read(o+0x3c,8)))
        color.append({'mode':mode,'mapped':mapped,'selector':selector,'matrix_words':coeff})
    cc=next(x for x in color if x['mode']==13);assert (cc['mapped'],cc['selector'],cc['matrix_words'])==(8,6,[866,-27,996,69])
    sweep=[]
    for native in range(9):
        v.u.mem_write(p,bytes(4096));v.u.mem_write(o,bytes(4096))
        v.run(0x324fe34,0x70000000,{0:o,1:native,2:1,3:0});idx=v.u32(o)
        for off,val in [(0x12c,1),(0x130,8),(0x124,18),(0x128,18),(0x13c,idx),(0x10c,8),(0x17c,2)]: v.put32(p+off,val)
        v.run(0x323b400,0x70000000,{0:p,1:o})
        sweep.append({'native':native,'index':idx,'gain':im.data[0xc0274+0xaf50+idx],
                      'words':list(struct.unpack('<4h',v.u.mem_read(o+0x3c,8)))})
    cc['color_sweep']=sweep
    cc['ui_conversion']=ui
    cc['key_table_address']='0x3766458'
    cc['keys']=list(struct.unpack('<4I',im.read(0x3766458+5*16,16)))
    cc['template_raw_u16']=list(struct.unpack('<4H',im.data[0xc0274+0xaed8:0xc0274+0xaee0]))
    v.u.mem_write(p,struct.pack('<4I',0,1,8,0))
    v.run(0x323ffec,0x70000000,{0:p})
    cc['extra_3d_selector']=v.x(0)&255
    packing=[]
    for vals in [(866,-27,996,69),(974,-12,946,-14),(0,-1,4095,-4096)]:
        for upper in (0,0xa000,0xe000):
            v.u.mem_write(p+0x1da,struct.pack('<4h',*vals));v.u.mem_write(o+0x1ec,struct.pack('<4H',*([upper]*4)))
            v.run(0x16953b0,0x70000000,{0:p,1:o});actual=list(struct.unpack('<4H',v.u.mem_read(o+0x1ec,8)))
            assert actual==[upper|(x&0x1fff) for x in vals]
            packing.append({'input':vals,'upper':hex(upper),'output':actual})
    # Полная цепь сборщик -> упаковщик -> виртуальные адреса устройства.
    v.u.mem_map(0xff96c000,0x4000);v.u.mem_map(0xff000000,0x1000)
    writes=[]
    def capture(uc,access,address,size,value,user):
        if address in (0xff96c634,0xff96c638):
            writes.append({'address':hex(address),'size':size,'value':value,'pc':hex(uc.reg_read(reg.UC_ARM64_REG_PC))})
    v.u.hook_add(UC_HOOK_MEM_WRITE,capture,begin=0xff96c000,end=0xff96ffff)
    general=o;registers=0x60020000;register_cases=[]
    for case in sweep:
        v.u.mem_write(p,bytes(4096));v.u.mem_write(general,bytes(4096))
        for off,val in [(0x12c,1),(0x130,8),(0x124,18),(0x128,18),(0x13c,case['index']),(0x10c,8),(0x17c,2)]:v.put32(p+off,val)
        v.run(0x32335bc,0x32335d4,{19:p,21:general+0x96c})
        words=list(struct.unpack('<4h',v.u.mem_read(general+0xb46,8)))
        assert words==case['words'] and v.u32(p+0x178)==0x80
        for upper in (0,0xa000,0xe000):
            v.u.mem_write(registers,bytes(4096))
            v.u.mem_write(registers+0x1ec,struct.pack('<4H',*([upper]*4)))
            v.run(0x3233bb8,0x70000000,{0:general,1:0x80,2:registers})
            packed=list(struct.unpack('<4H',v.u.mem_read(registers+0x1ec,8)))
            assert packed==[upper|(x&0x1fff) for x in words]
            writes.clear();v.run(0x3233be4,0x70000000,{0:0x80,1:registers})
            expected=list(struct.unpack('<2I',struct.pack('<4H',*packed)))
            assert [(w['address'],w['size'],w['value']) for w in writes]==[('0xff96c634',4,expected[0]),('0xff96c638',4,expected[1])]
            register_cases.append({'index':case['index'],'upper':hex(upper),'packed':packed,'writes':list(writes)})
    writes.clear();v.run(0x3233be4,0x70000000,{0:0,1:registers});assert not writes
    cc['register_chain']={'assembler':'0x32335bc..0x32335d4','packing_caller':'0x3233bb8','transmitter':'0x3233be4',
                          'descriptor':'0x1bfc250','descriptor_also_found':'0x1bfcb20',
                          'negative_control_mask_zero':True,'cases':register_cases,
                          'warning':'записи только в виртуальную память Unicorn, не физическое устройство'}
    updates=[];param=bytes.fromhex('4433221188776655ccbbaa9900ffeedd');v.u.mem_write(p,param)
    for name,start,end in [('INIT',0x3052e04,0x3052e3c),('START',0x3052e48,0x3052e64),('WRITE',0x3052e88,0x3052e9c),('DEINIT',0x3052ecc,0x3052ee0)]:
        v.run(start,end,{0:p,19:p});size=v.x(1);updates.append({'stage':name,'fragment':hex(start)+'..'+hex(end),'command':hex(v.x(0)),'size':size,'payload_hex':bytes(v.u.mem_read(v.x(2),size)).hex()})
    af=[]
    for row in verified:
        if re.search(r'af|focus|lens',row['name'],re.I):
            entry=row['entry']; instructions=im.instructions(entry,entry+192)
            calls=[{'at':hex(addr),'target':op} for addr,n,m,op in instructions if m=='bl']
            item={'task':row['name'],'entry':hex(entry),'registration_call':row['call'],'direct_calls_first_192_bytes_static':calls}
            if calls:
                try:
                    stop=int(calls[0]['at'],16)
                    v.run(entry,stop,{0:0})
                    item['first_call_vm']={'stop':hex(stop),'target':calls[0]['target'],'x0':hex(v.x(0)),'note':'начальная память искусственная, функция-цель не вызвана'}
                except Exception as ex: item['first_call_vm_error']=str(ex)
            af.append(item)
    allrows=verified+groups
    for row in allrows:
        if 1<=row['id']<=213:
            row['default_policy_candidate']=struct.unpack('<I',im.read(0x1de5548+4*(row['id']-1),4))[0]
    for item,helper,caller in zip(updates,[0x3052e04,0x3052e48,0x3052e70,0x3052eac],[0x2d6afbc,0x2d6b074,0x2d6b154,0x2d6ae70]):
        item.update({'helper':hex(helper),'static_caller':hex(caller),'packager':'0x3052dbc','transport_call':'0x3052df4 -> 0x17eecb8'})
    with (HERE/'Задачи.tsv').open('w',encoding='utf-8-sig',newline='') as f:
        w=csv.DictWriter(f,fieldnames=['id','name','priority','stack_bytes','entry','argument','default_policy_candidate','call','start','method'],delimiter='\t',extrasaction='ignore',lineterminator='\n');w.writeheader();w.writerows(allrows)
    result={'source':str(SOURCE.relative_to(PROJECT)),'sha256':sha,'blocks':[{'base':hex(a),'size':len(b),'sha256':hashlib.sha256(b).hexdigest()} for a,b in im.blocks], 'task_registration':{'creator':'0x17edb98','static_call_count':len(candidates),'static_named_count':sum(bool(r.get('name')) for r in candidates),'verified':verified,'factories':groups,'skipped':skipped,'bridge':bridge,'candidates':candidates},'dispatcher':dispatch,'linux_boot_rpmsg':linux,'color_chain':{'mode_fragment':'0x324f9a8','selector_function':'0x323b004','matrix_function':'0x323b400','template_dat_offset':'0xc0274','template_pointer_location':'0x23dbc30','synthetic_context':{'12c':1,'124':18,'128':18,'13c':4,'10c':8,'17c':2,'180':0},'modes':color,'packing_function':'0x16953b0','packing':packing},'update':updates,'autofocus':af,'virtual_fragment_runs':v.count,'source_unchanged':hashlib.sha256(SOURCE.read_bytes()).hexdigest()==sha,'limits':['No whole camera boot, hardware, task scheduling or physical writes','Static constants and isolated synthetic contexts do not establish runtime reachability','AF task names do not identify focus algorithms']}
    assert result['source_unchanged']
    (HERE/'Результаты.json').write_text(json.dumps(result,ensure_ascii=False,indent=2)+'\n',encoding='utf-8')
    print(json.dumps({'verified':len(verified),'groups':len(groups),'skipped':len(skipped),'runs':v.count,'linux':linux['boot_registers'],'classic_chrome':cc,'update':updates,'af':af},ensure_ascii=False,indent=2))

if __name__=='__main__': main()
