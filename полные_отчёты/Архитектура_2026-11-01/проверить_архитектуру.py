"""Прочитать состав X-H2 5.30 и проверить два фрагмента диспетчера.

Ничего из файловой системы камеры не запускается и не распаковывается в
исполняемые файлы на компьютере. На диск записываются только перечни и отчёт.
Исходный DAT открыт для чтения. Проверки ARM64 используют виртуальную память.
"""
from pathlib import Path
from collections import Counter
import csv
import hashlib
import importlib.util
import json
import re
import struct
import sys
import zlib

HERE = Path(__file__).resolve().parent
ROOT = HERE.parent
sys.path.insert(0, str(ROOT / 'инструменты'))
spec = importlib.util.spec_from_file_location('xh2_arch_base', ROOT / 'анализ_файла.py')
base = importlib.util.module_from_spec(spec)
spec.loader.exec_module(base)
from capstone import Cs, CS_ARCH_ARM64, CS_MODE_ARM
from unicorn import Uc, UC_ARCH_ARM64, UC_MODE_ARM, UC_PROT_READ, UC_PROT_EXEC
from unicorn.arm64_const import (UC_ARM64_REG_X0, UC_ARM64_REG_X1,
                                UC_ARM64_REG_X2, UC_ARM64_REG_PC, UC_ARM64_REG_SP)


def digest(b):
    return hashlib.sha256(b).hexdigest()


def gzip_at(data, offset):
    dec = zlib.decompressobj(31)
    packed = data[offset:]
    unpacked = dec.decompress(packed, 64 * 1024 * 1024)
    assert dec.eof, 'Поток не завершён или превышает предел размера'
    used = len(packed) - len(dec.unused_data)
    return unpacked, used


def cpio_entries(data):
    pos = 0
    entries = []
    payloads = {}
    kinds = {0o040000: 'каталог', 0o100000: 'обычный файл',
             0o120000: 'символическая ссылка', 0o020000: 'символьное устройство',
             0o060000: 'блочное устройство'}
    while True:
        assert pos + 110 <= len(data)
        header = data[pos:pos+110]
        assert header[:6] == b'070701'
        assert re.fullmatch(rb'[0-9a-fA-F]{104}', header[6:])
        fields = [int(header[6+i*8:14+i*8], 16) for i in range(13)]
        mode, size, nsize = fields[1], fields[6], fields[11]
        assert 0 < nsize < 4096 and pos + 110 + nsize <= len(data)
        name_raw = data[pos+110:pos+110+nsize]
        assert name_raw[-1] == 0
        name = name_raw[:-1].decode('utf-8')
        start = (pos + 110 + nsize + 3) & ~3
        assert start + size <= len(data)
        pos = (start + size + 3) & ~3
        if name == 'TRAILER!!!':
            assert size == 0
            return entries, payloads, pos
        assert name not in payloads
        payloads[name] = memoryview(data)[start:start+size]
        entries.append({'path': name, 'kind': kinds.get(mode & 0o170000, 'другой'),
                        'mode': oct(mode), 'size': size, 'cpio_data_offset': hex(start)})


def elf_info(data):
    assert data[:6] == b'\x7fELF\x02\x01'
    h = struct.unpack_from('<16sHHIQQQIHHHHHH', data)
    assert h[11] == 64
    sections = [struct.unpack_from('<IIQQQQIIQQ', data, h[6]+j*h[11])
                for j in range(h[12])]
    names_row = sections[h[13]]
    names = data[names_row[4]:names_row[4]+names_row[5]]
    named = {bytes(names[r[0]:]).split(b'\0', 1)[0].decode('ascii'): r for r in sections}
    result = {'class': 64, 'machine': h[2], 'type': h[1], 'sections': list(named)}
    result['source_files'] = []
    result['defined_global_functions'] = []
    if '.symtab' in named:
        row = named['.symtab']
        strings_row = sections[row[6]]
        strings = data[strings_row[4]:strings_row[4]+strings_row[5]]
        assert row[9] == 24
        for pos in range(row[4], row[4]+row[5], 24):
            name, info, other, shndx, value, size = struct.unpack_from('<IBBHQQ', data, pos)
            label = bytes(strings[name:]).split(b'\0', 1)[0].decode('utf-8', errors='replace')
            if (info & 15) == 4:
                result['source_files'].append(label)
            if (info & 15) == 2 and info >> 4 in (1, 2) and shndx != 0:
                result['defined_global_functions'].append(label)
    for section in ('.comment', '.dynstr'):
        if section in named:
            row = named[section]
            values = bytes(data[row[4]:row[4]+row[5]]).split(b'\0')
            if section == '.comment':
                result['compiler_strings'] = [v.decode('ascii', errors='replace') for v in values if v]
            else:
                result['cpp_runtime_references'] = [v.decode('ascii', errors='replace') for v in values
                                                    if b'libstdc++' in v or b'CXXABI' in v]
    result['debug_info_present'] = '.debug_info' in named
    return result


def ar_objects(data):
    assert data[:8] == b'!<arch>\n'
    pos, names = 8, b''
    result = []
    while pos + 60 <= len(data):
        h = data[pos:pos+60]
        assert h[58:60] == b'`\n'
        name = h[:16].decode('ascii').strip()
        size = int(h[48:58])
        content = data[pos+60:pos+60+size]
        assert len(content) == size
        if name == '//':
            names = content
        elif name not in ('/', '/SYM64/'):
            if name.startswith('/') and name[1:].isdigit():
                name = names[int(name[1:]):].split(b'/\n', 1)[0].decode('ascii')
            result.append({'object': name.rstrip('/'), 'bytes': size,
                           'sha256': digest(content), **elf_info(content)})
        pos += 60 + size + size % 2
    assert pos == len(data)
    return result


def verify_dispatch(low):
    uc = Uc(UC_ARCH_ARM64, UC_MODE_ARM)
    uc.mem_map(0x40000, (len(low)+4095) & ~4095)
    uc.mem_write(0x40000, low)
    uc.mem_protect(0x40000, (len(low)+4095) & ~4095, UC_PROT_READ | UC_PROT_EXEC)
    uc.mem_map(0x70000000, 0x10000)
    stack = 0x7000F000
    callback, argument = 0x12345678, 42

    # Непосредственно перед вызовом службы очереди проверяются её аргументы.
    uc.reg_write(UC_ARM64_REG_SP, stack)
    uc.reg_write(UC_ARM64_REG_X0, callback)
    uc.reg_write(UC_ARM64_REG_X1, argument)
    uc.emu_start(0x55FBC, 0x55FDC, count=100)
    assert uc.reg_read(UC_ARM64_REG_PC) == 0x55FDC
    queue = uc.reg_read(UC_ARM64_REG_X0)
    message = uc.reg_read(UC_ARM64_REG_X1)
    assert queue == 0x62890
    assert uc.reg_read(UC_ARM64_REG_X2) == 0
    assert struct.unpack('<2I', uc.mem_read(message, 8)) == (callback, argument)

    # Подставляется результат успешного получения сообщения. Вызов функции не исполняется.
    uc.reg_write(UC_ARM64_REG_SP, stack)
    uc.reg_write(UC_ARM64_REG_X0, 0)
    uc.mem_write(stack+0x38, struct.pack('<2I', callback, argument))
    uc.emu_start(0x55F98, 0x55FA4, count=100)
    assert uc.reg_read(UC_ARM64_REG_PC) == 0x55FA4
    assert uc.reg_read(UC_ARM64_REG_X0) == argument
    assert uc.reg_read(UC_ARM64_REG_X1) == callback
    return {'runs': 2, 'queue_name': 'uiSYSQ', 'task_name': 'uiSYST',
            'queue_pointer_in_this_module': hex(queue),
            'message_layout': 'two 32-bit words: function address, argument',
            'synthetic_callback': hex(callback), 'synthetic_argument': argument,
            'send_preparation_entry': '0x00055FBC', 'send_stop': '0x00055FDC',
            'receive_preparation_entry': '0x00055F98', 'receive_stop': '0x00055FA4',
            'actual_queue_service_and_callback_not_executed': True}


def main():
    raw = base.SOURCE.read_bytes()
    assert digest(raw) == base.EXPECTED_SHA256
    data = raw.translate(base.TRANSLATION)
    old = json.loads((ROOT/'сведения.json').read_text(encoding='utf-8'))
    blocks = []
    decoded_blocks = {}
    for b in old['fflz_blocks']:
        offset = int(b['file_offset'], 16)
        unpacked = base.unpack_fflz(data, offset)
        assert len(unpacked) == b['unpacked_size'] and digest(unpacked) == b['decoded_sha256']
        decoded_blocks[offset] = unpacked
        blocks.append({**b, 'first_32_bytes': unpacked[:32].hex(' ')})
    low = data[0x60274:0x60274+0x1E340]
    assert struct.unpack_from('<Q', low, 8)[0] == 0x40000
    assert b'ThreadX Cortex-A5x-SMP/ARM Version G5.9.5.5' in low
    assert low[0x1E230:0x1E230+7] == b'uiSYSQ\0'
    assert low[0x1E238:0x1E238+7] == b'uiSYST\0'

    kh = struct.unpack_from('<2I6Q2I', data, 0x3CB0274)
    assert kh[8] == 0x644D5241 and kh[5:8] == (0, 0, 0)
    kernel = {'dat_offset': '0x03CB0274', 'text_offset': hex(kh[2]),
              'effective_memory_image_size': kh[3], 'flags': hex(kh[4]),
              'magic': hex(kh[8]),
              'size_note': 'Header image_size describes required effective image size; not a parsed partition boundary.'}
    config, config_packed = gzip_at(data, 0x413B474)
    assert b'Linux/arm64 4.9.92 Kernel Configuration' in config
    config_lines = config.decode('utf-8').splitlines()
    kernel['selected_build_configuration'] = [v for v in config_lines if re.match(
        r'CONFIG_(?:ARM64|SMP|INITRAMFS_SOURCE|NET|CFG80211|BRCMFMAC|RPMSG[^=]*|VIRTIO[^=]*)=', v)]

    fs, fs_packed = gzip_at(data, 0x42DFDCC)
    entries, payloads, parsed = cpio_entries(fs)
    assert len(entries) == 3202 and Counter(v['kind'] for v in entries)['обычный файл'] == 2355
    objects = ar_objects(bytes(payloads['usr/lib/libff_api.a']))
    assert [v['object'] for v in objects] == ['wlan_wld_api.o', 'ff_wlan_api.o',
                                            'wpa_ctrl.o', 'os_unix.o', 'common.o']
    allowed_texts = ['etc/inittab', 'etc/init.d/ffsys-init.sh',
                     'etc/init.d/rpmsg-daemon', 'etc/rpmsg-daemon.conf']
    snippets = {name: bytes(payloads[name]).decode('utf-8') for name in allowed_texts}
    assert 'null::sysinit:/usr/bin/rpmsg-daemon' in snippets['etc/inittab']
    assert 'null::sysinit:/etc/init.d/ffsys-init.sh' in snippets['etc/inittab']
    programs = {name: elf_info(bytes(payloads[name])) for name in [
        'usr/local/bin/fujifilm/ff_ftp.exe', 'usr/local/bin/fujifilm/ff_frameio.exe',
        'usr/local/bin/fujifilm/ff_c2pa.exe', 'usr/bin/rpmsg-daemon']}
    assert all(p['machine'] == 183 for p in programs.values())
    vdso = data[0x4137274:0x4137274+0xC88]
    assert b'linux-vdso.so.1\0' in vdso and b'__kernel_gettimeofday\0' in vdso

    with (HERE/'Каталог_содержимого_Linux.tsv').open('w', encoding='utf-8-sig', newline='') as f:
        w = csv.DictWriter(f, fieldnames=list(entries[0]), delimiter='\t', lineterminator='\n')
        w.writeheader()
        w.writerows(entries)
    with (HERE/'Модули_и_функции_библиотеки_связи.tsv').open('w', encoding='utf-8-sig', newline='') as f:
        w = csv.writer(f, delimiter='\t', lineterminator='\n')
        w.writerow(['объектный_модуль', 'исходный_файл_из_таблицы_символов', 'функция'])
        for obj in objects:
            for func in obj['defined_global_functions']:
                w.writerow([obj['object'], ', '.join(obj['source_files']), func])
    cs = Cs(CS_ARCH_ARM64, CS_MODE_ARM)
    commands = []
    for start, end in [(0x55F68, 0x55FF0), (0x55FF0, 0x5609C), (0x58420, 0x58478)]:
        commands.append(f'; {start:#010x} .. {end:#010x}')
        commands.extend(f'{i.address:08X}  {i.bytes.hex(" ").upper():11}  {i.mnemonic:7} {i.op_str}'
                        for i in cs.disasm(low[start-0x40000:end-0x40000], start))
    (HERE/'Системная_очередь_и_начало_запуска.asm').write_text('\n'.join(commands)+'\n', encoding='utf-8')
    proof = {'date': '2026-11-01', 'source': str(base.SOURCE), 'source_sha256': digest(raw),
             'fflz_blocks': blocks, 'kernel': kernel,
             'kernel_config': {'dat_offset': '0x0413B474', 'packed_bytes': config_packed,
                               'decoded_bytes': len(config), 'sha256': digest(config)},
             'vdso': {'dat_offset': '0x04137274', 'name': 'linux-vdso.so.1',
                      'is_separate_main_application': False, 'elf': elf_info(vdso)},
             'linux_filesystem': {'dat_offset': '0x042DFDCC', 'packed_bytes': fs_packed,
                                  'decoded_bytes': len(fs), 'sha256': digest(fs),
                                  'cpio_bytes_through_trailer': parsed,
                                  'entries_excluding_trailer': len(entries),
                                  'counts_by_kind': dict(Counter(v['kind'] for v in entries)),
                                  'counts_by_top_directory': dict(Counter(v['path'].split('/')[0] for v in entries))},
             'startup_texts': snippets, 'library_objects': objects, 'linux_programs': programs,
             'system_queue': verify_dispatch(low),
             'source_unchanged': digest(base.SOURCE.read_bytes()) == digest(raw),
             'limits': ['No whole-camera boot or physical device execution',
                        'Original proprietary source tree not recovered',
                        'No complete assignment of tasks to CPU cores',
                        'Presence in archive does not establish runtime activation']}
    assert proof['source_unchanged']
    (HERE/'Проверка_архитектуры.json').write_text(json.dumps(proof, ensure_ascii=False, indent=2)+'\n', encoding='utf-8')
    print(json.dumps({'source_unchanged': True, 'filesystem': proof['linux_filesystem'],
                      'objects': [{'object': o['object'], 'source_files': o['source_files'],
                                   'function_count': len(o['defined_global_functions']),
                                   'compiler': o.get('compiler_strings'), 'debug': o['debug_info_present']}
                                  for o in objects], 'queue': proof['system_queue']},
                     ensure_ascii=True, indent=2))


if __name__ == '__main__':
    main()
