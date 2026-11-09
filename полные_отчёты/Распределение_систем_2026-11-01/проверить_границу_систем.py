"""Проверка регистрации задач, перехода к Linux и состава Linux-служб.

Исполнение ограничено подготовительными фрагментами ARM64 в виртуальной памяти.
Сами задачи, ядро Linux, службы, обращения к устройствам и libc не запускаются.
"""
from pathlib import Path
import importlib.util
import json
import re
import struct
import csv
import hashlib

HERE = Path(__file__).resolve().parent
ROOT = HERE.parent
spec = importlib.util.spec_from_file_location('xh2_dist', HERE/'исследовать_распределение.py')
dist = importlib.util.module_from_spec(spec)
spec.loader.exec_module(dist)
spec = importlib.util.spec_from_file_location('xh2_arch', ROOT/'Архитектура_2026-11-01/проверить_архитектуру.py')
arch = importlib.util.module_from_spec(spec)
spec.loader.exec_module(arch)
from unicorn import Uc, UC_ARCH_ARM64, UC_MODE_ARM, UC_PROT_READ, UC_PROT_EXEC
from unicorn import arm64_const as regs


class VM:
    def __init__(self, image):
        self.uc = Uc(UC_ARCH_ARM64, UC_MODE_ARM)
        for start, b in image.blocks:
            n = (len(b)+4095)&~4095
            self.uc.mem_map(start, n)
            self.uc.mem_write(start, b)
            self.uc.mem_protect(start, n, UC_PROT_READ | UC_PROT_EXEC)
        self.uc.mem_map(0x60000000, 0x40000)
        self.uc.mem_map(0x70000000, 0x10000)
        # Только искусственная рабочая память для глобальных записей программы.
        a_end = 0x1101000+((len(image.blocks[1][1])+4095)&~4095)
        self.uc.mem_map(a_end, 0x29AE000-a_end)
        b_end = 0x29AE000+((len(image.blocks[2][1])+4095)&~4095)
        self.uc.mem_map(b_end, 0x6000000-b_end)
        self.count = 0

    def reset(self):
        for j in range(31):
            self.uc.reg_write(getattr(regs, f'UC_ARM64_REG_X{j}'), 0)
        self.uc.reg_write(regs.UC_ARM64_REG_SP, 0x7000F000)
        self.uc.mem_write(0x7000E000, bytes(0x2000))

    def run(self, start, end, inputs=None):
        for n, value in (inputs or {}).items():
            self.uc.reg_write(getattr(regs, f'UC_ARM64_REG_X{n}'), value)
        self.uc.emu_start(start, end, timeout=500000, count=2000)
        assert self.uc.reg_read(regs.UC_ARM64_REG_PC) == end, hex(start)
        self.count += 1

    def reg(self, n):
        return self.uc.reg_read(getattr(regs, f'UC_ARM64_REG_X{n}'))

    def u32(self, a):
        return struct.unpack('<I', self.uc.mem_read(a, 4))[0]

    def u64(self, a):
        return struct.unpack('<Q', self.uc.mem_read(a, 8))[0]


def descriptor(vm, pointer):
    return {'id': vm.u32(pointer), 'name_pointer': vm.u64(pointer+8),
            'priority': vm.u32(pointer+16), 'stack_bytes': vm.u32(pointer+20),
            'entry': vm.u64(pointer+24), 'argument': vm.u64(pointer+32)}


def bridge(vm, record):
    """Проследить исходный адрес задачи до общей начальной функции ThreadX."""
    source, tcb = 0x60000000, 0x60010000
    data = bytearray(48)
    for name, off, fmt in [('id',0,'I'), ('name_pointer',8,'Q'), ('priority',16,'I'),
                           ('stack_bytes',20,'I'), ('entry',24,'Q'), ('argument',32,'Q')]:
        struct.pack_into('<'+fmt, data, off, record[name])
    vm.reset()
    vm.uc.mem_write(source, bytes(data))
    # Подлинное преобразование верхнего описателя в нижний.
    vm.run(0x14CE0BC, 0x14CE0D8, {19: source})
    lower = 0x7000F040
    assert vm.u64(lower+16) == record['entry']
    assert vm.u64(lower+8) == record['argument']
    # Перенос адреса и аргумента в управляющую запись системной задачи.
    vm.run(0x4CD74, 0x4CDAC, {19: lower, 20: tcb})
    assert vm.u64(tcb+0x178) == record['entry']
    assert vm.u64(tcb+0x170) == record['argument']
    assert vm.u64(tcb+0x198) == record['argument']
    # Аргументы непосредственно перед настоящим вызовом создания потока ThreadX.
    vm.uc.mem_write(tcb+0x10, struct.pack('<Q', 0x60020000))
    vm.run(0x4CE54, 0x4CE88, {19: lower, 20: tcb, 21: tcb, 22: tcb+0x15C})
    assert vm.reg(2) == 0x5609C and vm.reg(3) == tcb
    # Общая начальная функция берёт именно исходную функцию и аргумент.
    vm.run(0x560C0, 0x560C8, {19: tcb})
    assert vm.reg(1) == record['entry'] and vm.reg(0) == record['argument']


def elf_tables(b):
    h = struct.unpack_from('<16sHHIQQQIHHHHHH', b)
    assert h[0][:6] == b'\x7fELF\x02\x01' and h[2] == 183
    rows = [struct.unpack_from('<IIQQQQIIQQ', b, h[6]+j*h[11]) for j in range(h[12])]
    n = rows[h[13]]
    ns = b[n[4]:n[4]+n[5]]
    sections = {ns[r[0]:].split(b'\0',1)[0].decode(): r for r in rows}
    r = sections['.dynsym']
    sr = rows[r[6]]
    st = b[sr[4]:sr[4]+sr[5]]
    symbols = []
    for off in range(r[4], r[4]+r[5], 24):
        name, info, other, sh, value, size = struct.unpack_from('<IBBHQQ', b, off)
        symbols.append({'name': st[name:].split(b'\0',1)[0].decode(errors='replace'),
                        'defined': sh != 0, 'value': value, 'size': size})
    return sections, symbols


def main():
    image = dist.Image()
    vm = VM(image)
    static = [dist.task_argument(image, call) for call, target in image.calls({0x14CE004})]
    verified, skipped = [], []
    for record in static:
        if not record.get('name') or record.get('entry') is None:
            continue
        call = int(record['call'], 16)
        instructions = image.instructions(call-192, call)
        # Начало чистого участка заполнения описателя: константа номера задачи.
        ptrs=[(a,args) for a,n,op,args in instructions if op=='add' and
              re.fullmatch(r'x0, sp, #(?:0x[0-9a-f]+|\d+)',args)]
        starts=[]
        if ptrs:
            offset=int(ptrs[-1][1].split('#')[1],0)
            starts=[a for a,n,op,args in instructions if op=='str' and
                    re.fullmatch(r'w\d+, \[sp, #(?:0x[0-9a-f]+|\d+)\]',args) and
                    int(args.split('#')[1][:-1],0)==offset]
        try:
            assert starts, 'Не найдено начало заполнения описателя'
            vm.reset()
            start = starts[-1]
            prior=dist.task_argument(image,start)['register_values']
            supplied={int(k):v for k,v in prior.items() if v is not None and int(k)!=29}
            vm.run(start, call, supplied)
            actual = descriptor(vm, vm.reg(0))
            for field in ['id','name_pointer','priority','stack_bytes','entry']:
                assert actual[field] == record[field], (field,actual[field],record[field])
            assert image.string(actual['name_pointer']) == record['name']
            bridge(vm, actual)
            verified.append({**actual, 'name': record['name'], 'call': record['call'],
                             'preparation_start': hex(start),
                             'supplied_initial_registers':{str(k):hex(v) for k,v in supplied.items()},
                             'method': 'unmodified ARM64 fragments; constant-derived input registers'})
        except Exception as error:
            skipped.append({'call':record['call'], 'name':record['name'], 'reason':str(error)})

    # Групповые фабрики фото- и видеозадач.
    group_rows = []
    for call, target in image.calls({0x2E7341C,0x2E977B4}):
        values = dist.task_argument(image, call)['argument_registers']
        name = image.string(values['x1'])
        assert name and values['x0'] is not None and values['x2'] is not None
        vm.reset()
        if target == 0x2E7341C:
            start, end, inputs = 0x2E73474, 0x2E734A0, {19:values['x0'],20:values['x2'],21:values['x1']}
        else:
            start, end, inputs = 0x2E977FC, 0x2E97828, {21:values['x0'],20:values['x1'],19:values['x2']}
        vm.run(start,end,inputs)
        rec = descriptor(vm,vm.reg(0))
        assert rec['id'] == values['x0'] and image.string(rec['name_pointer']) == name
        bridge(vm,rec)
        group_rows.append({**rec,'name':name,'factory_call':hex(call),'factory':hex(target),
                           'method':'unmodified factory tail; supplied constant caller arguments'})
    for j in range(17):
        address = 0x33FA930 if j == 16 else 0x33FA9D8+j*24
        tid,pad,nameptr,priority,extra = struct.unpack('<IIQII',image.read(address,24))
        name = image.string(nameptr)
        assert name
        vm.reset()
        vm.run(0x2E39C7C,0x2E39CA8,{21:tid,20:nameptr,19:priority})
        rec = descriptor(vm,vm.reg(0))
        assert rec['id'] == tid and rec['name_pointer'] == nameptr
        bridge(vm,rec)
        group_rows.append({**rec,'name':name,'source_table_record':hex(address),
                           'method':'unmodified factory tail; parameters from original table'})
    for j in range(3):
        address = 0x15FF3C0+0x50+j*0x78
        tid,pad,nameptr,priority,stack = struct.unpack('<IIQII',image.read(address,24))
        name = image.string(nameptr)
        vm.reset()
        vm.run(0x1127728,0x112774C,{19:tid,22:nameptr,21:priority,20:stack})
        rec = descriptor(vm,vm.reg(0))
        assert rec['id'] == tid and rec['name_pointer'] == nameptr
        bridge(vm,rec)
        group_rows.append({**rec,'name':name,'source_table_record':hex(address),
                           'method':'unmodified factory tail; parameters from original table'})

    # Описатель linux создаётся динамической разновидностью того же API ThreadX.
    vm.reset()
    vm.run(0x2EDB6B0,0x2EDB6F8)
    assert vm.reg(0) == 192 and vm.reg(1) == 0
    pointer = vm.reg(2)
    linux = {'id':192,'name_pointer':vm.u64(pointer+40), 'priority':vm.u32(pointer+8),
             'stack_bytes':vm.u64(pointer+16),'entry':vm.u64(pointer),'argument':vm.u64(pointer+32)}
    assert image.string(linux['name_pointer']) == 'linux' and linux['entry'] == 0x2EDB610
    bridge(vm,linux)
    vm.reset()
    vm.run(0x2EDB708,0x2EDB710)
    assert vm.reg(0) == 192 and vm.reg(1) == 4
    # Маска разрешённых ядер 4 преобразуется в исключение 0xB.
    vm.run(0x56BC8,0x56BD4,{21:4,19:0x60010000})
    assert vm.reg(1) == 0xB
    vm.uc.mem_write(0x60010100,struct.pack('<I',0))
    vm.run(0x45504,0x4553C,{19:0x60010000,21:0xB})
    assert vm.u32(0x60010110) == 0xB and vm.u32(0x60010114) == 4
    assert vm.u32(0x60010100) == 2
    # Подготовка вызова ядра; сам переход в ядро не выполняется.
    vm.reset()
    vm.run(0x3197178,0x319718C)
    boot_args = {f'x{j}':hex(vm.reg(j)) for j in range(5)}
    assert boot_args == {'x0':'0x7010000','x1':'0x0','x2':'0x0','x3':'0x0','x4':'0x7080000'}

    # Файлы и импортируемые функции Linux, без запуска этих программ.
    fs,_ = arch.gzip_at(image.data,0x42DFDCC)
    _, files, _ = arch.cpio_entries(fs)
    linux_files = {}
    wanted = ['usr/bin/rpmsg-daemon','usr/bin/isgc_futil_daemon',
              'usr/local/bin/fujifilm/ff_ftp.exe','usr/local/bin/fujifilm/ff_frameio.exe',
              'usr/local/bin/fujifilm/ff_c2pa.exe']
    for path in wanted:
        b = bytes(files[path])
        sections,symbols = elf_tables(b)
        linux_files[path] = {'sha256':hashlib.sha256(b).hexdigest(),
                            'imports':[s['name'] for s in symbols if not s['defined'] and s['name']],
                            'handler_names':sorted({z.group().decode() for z in re.finditer(rb'do_[a-z_]+_cmd',b)})}
    channel = b'rpmsg-socket-api-channel'
    assert channel in image.blocks[2][1] and channel in bytes(files['usr/bin/rpmsg-daemon'])
    assert {'socket','connect','send','recv','system'} <= set(linux_files['usr/bin/rpmsg-daemon']['imports'])

    # В обработчике Linux три поля запроса становятся аргументами socket().
    daemon=bytes(files['usr/bin/rpmsg-daemon'])
    sections,symbols=elf_tables(daemon)
    rel=sections['.rela.plt'];plt=sections['.plt']
    socket_plt=None
    for index,off in enumerate(range(rel[4],rel[4]+rel[5],24)):
        got,info,addend=struct.unpack_from('<QQq',daemon,off)
        if symbols[info>>32]['name']=='socket':
            socket_plt=plt[3]+32+16*index
            assert got==0x434000 and socket_plt==0x403160
    assert socket_plt is not None
    h=struct.unpack_from('<16sHHIQQQIHHHHHH',daemon)
    segments=[struct.unpack_from('<IIQQQQQQ',daemon,h[5]+j*h[9]) for j in range(h[10])]
    load=[r for r in segments if r[0]==1]
    low=min(r[3]&~4095 for r in load)
    high=max((r[3]+r[6]+4095)&~4095 for r in load)
    vm.uc.mem_map(low,high-low)
    for r in load:
        vm.uc.mem_write(r[3],daemon[r[2]:r[2]+r[5]])
    vm.reset()
    vm.uc.mem_write(0x60000008,struct.pack('<Q',0x60001000))
    vm.uc.mem_write(0x6000100C,struct.pack('<3I',2,1,6))
    vm.uc.reg_write(regs.UC_ARM64_REG_X29,0x7000E000)
    vm.run(0x40C3A8,0x40C3C8,{23:0x60000000})
    assert [vm.reg(j) for j in range(3)]==[2,1,6]
    text=sections['.text']
    instruction=struct.unpack_from('<I',daemon,text[4]+0x40C3C8-text[3])[0]
    immediate=instruction&0x3FFFFFF
    if immediate&(1<<25):immediate-=1<<26
    assert instruction&0xFC000000==0x94000000 and 0x40C3C8+immediate*4==socket_plt
    socket_request={'program':'usr/bin/rpmsg-daemon','fragment':'0x0040C3A8..0x0040C3C8',
                    'request_fields':['+0x0C','+0x10','+0x14'],
                    'synthetic_values':[2,1,6],'prepared_socket_arguments':[2,1,6],
                    'socket_plt':hex(socket_plt),'call_address':'0x0040C3C8',
                    'libc_and_network_not_executed':True}

    all_rows = verified+group_rows+[{**linux,'name':'linux','method':'unmodified creation tail and ThreadX bridge'}]
    for row in all_rows:
        if row['id'] <= 213:
            policy = struct.unpack('<I', image.read(0x1AC89C8+(row['id']-1)*4,4))[0]
            row['core_policy_from_default_table'] = policy
            row['default_core_slot'] = policy if policy < 4 else None
        if row['id'] == 192:
            row['explicit_allowed_core_mask'] = '0x4'
            row['explicit_core_slot'] = 2
    with (HERE/'Проверенные_задачи_ThreadX.tsv').open('w',encoding='utf-8-sig',newline='') as f:
        w=csv.writer(f,delimiter='\t',lineterminator='\n')
        w.writerow(['номер','имя','приоритет','стек_байт','адрес_начала','обычное_ядро','способ_проверки'])
        method_labels = {
            'unmodified ARM64 fragments; constant-derived input registers':
                'Исходные фрагменты ARM64; входные регистры восстановлены из констант',
            'unmodified factory tail; parameters from original table':
                'Исходный конец функции создания; параметры из таблицы прошивки',
            'unmodified factory tail; supplied constant caller arguments':
                'Исходный конец функции создания; постоянные аргументы вызывающего кода',
            'unmodified creation tail and ThreadX bridge':
                'Исходная подготовка описателя и передача в ThreadX',
        }
        for row in sorted(all_rows,key=lambda r:(r['id'],r['name'])):
            w.writerow([row['id'],row['name'],row['priority'],row['stack_bytes'],hex(row['entry']),
                        row.get('explicit_core_slot',row.get('default_core_slot')),method_labels[row['method']]])
    result={'source_sha256':hashlib.sha256(image.raw).hexdigest(),
            'source_unchanged':hashlib.sha256(dist.base.SOURCE.read_bytes()).hexdigest()==hashlib.sha256(image.raw).hexdigest(),
            'virtual_fragment_runs':vm.count,'verified_creation_records':len(all_rows),
            'unique_verified_task_ids':len({r['id'] for r in all_rows}),
            'static_preparations_skipped':skipped,'tasks':all_rows,
            'threadx_bridge':{'upper_creator':'0x014CE004','lower_creator':'0x0004CEB8',
                             'threadx_thread_create':'0x000442A0','threadx_start':'0x0005609C',
                             'original_task_entry_tcb_offset':'0x178'},
            'linux_launch':{'creation_call':'0x02EDB6F8','task_entry':'0x02EDB610',
                            'allowed_core_mask':'0x4','core_slot':2,
                            'secure_monitor_wrapper':'0x031972FC','context_save_and_boot':'0x03197000',
                            'kernel_call_instruction':'0x0319718C','arguments_before_kernel_call':boot_args,
                            'kernel_not_executed':True},
            'shared_channel':channel.decode(),'channel_setup_call_in_main_program':'0x02EDF688',
            'linux_programs':linux_files,'linux_socket_request':socket_request,
            'limits':['Separate unmodified fragments with artificial RAM, not a whole-camera boot',
                      'Task registration sites are not a live list of running tasks',
                      'Default task affinity can be changed by other code',
                      'No proof that every autofocus/ISP/DSP instruction runs on an ARM core',
                      'Not a complete map of every conditional function or hardware algorithm']}
    assert result['source_unchanged']
    (HERE/'Проверка_границы_систем.json').write_text(json.dumps(result,ensure_ascii=False,indent=2)+'\n',encoding='utf-8')
    lines=[]
    for start,end in [(0x14CE0BC,0x14CE128),(0x4CD74,0x4CDAC),(0x4CE54,0x4CE8C),
                      (0x560BC,0x560CC),(0x2EDB6A8,0x2EDB724),(0x2EDB610,0x2EDB6A8),
                      (0x3197000,0x3197190),(0x31972FC,0x3197318),(0x56BC8,0x56BD8),
                      (0x45504,0x4553C),(0x2EDF678,0x2EDF68C)]:
        lines.append(f'; {start:#010x} .. {end:#010x}')
        lines.extend(f'{a:08X}  {op:7} {args}' for a,n,op,args in image.instructions(start,end))
    (HERE/'ThreadX_запуск_Linux_и_канал_связи.asm').write_text('\n'.join(lines)+'\n',encoding='utf-8')
    print(json.dumps({k:result[k] for k in ['virtual_fragment_runs','verified_creation_records',
                      'unique_verified_task_ids','static_preparations_skipped','linux_launch','source_unchanged']},
                     ensure_ascii=True,indent=2))


if __name__=='__main__':
    main()
