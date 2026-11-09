"""Чтение признаков обновления в FWUP0028.DAT и проверка подготовки запросов.

Камера и накопители не используются. Сценарии из прошивки читаются как данные.
Машинные команды выполняются только в виртуальной памяти до вызова передачи.
"""
from pathlib import Path
import hashlib
import importlib.util
import json
import struct
import sys
import zlib

HERE = Path(__file__).resolve().parent
ROOT = HERE.parent
sys.path.insert(0, str(ROOT/'инструменты'))
spec = importlib.util.spec_from_file_location('xh2_update_base', ROOT/'анализ_файла.py')
base = importlib.util.module_from_spec(spec)
spec.loader.exec_module(base)
from capstone import Cs, CS_ARCH_ARM64, CS_MODE_ARM
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec
from unicorn import Uc, UC_ARCH_ARM64, UC_MODE_ARM, UC_PROT_READ, UC_PROT_EXEC
from unicorn.arm64_const import (UC_ARM64_REG_X0, UC_ARM64_REG_X1, UC_ARM64_REG_X2,
                                UC_ARM64_REG_X19, UC_ARM64_REG_SP, UC_ARM64_REG_PC)


def main():
    raw = base.SOURCE.read_bytes()
    sha = hashlib.sha256(raw).hexdigest()
    assert sha == base.EXPECTED_SHA256
    key = serialization.load_pem_public_key((ROOT/'инструменты/xh2_pubkey.pem').read_bytes())
    key.verify(raw[-72:], raw[:-72], ec.ECDSA(hashes.SHA256()))
    decoded = raw.translate(base.TRANSLATION)
    a = base.unpack_fflz(decoded, 0x300274)
    b = base.unpack_fflz(decoded, 0x840274)
    old = json.loads((ROOT/'сведения.json').read_text(encoding='utf-8'))
    for offset, block in [(0x300274, a), (0x840274, b)]:
        expected = next(v for v in old['fflz_blocks'] if int(v['file_offset'], 16) == offset)
        assert hashlib.sha256(block).hexdigest() == expected['decoded_sha256']

    labels = {}
    for text in ['A_UPDATE_INIT', 'A_UPDATE_START', 'A_UPDATE_WRITE', 'A_UPDATE_DEINIT',
                 'UI_ERR_UPDATE_NO_FILE', 'UI_ERR_UPDATE_BROKEN_FILE',
                 'UI_ERR_UPDATE_OLD_FILE', 'UI_ERR_UPDATE_MODEDIFFER',
                 'UI_ERR_UPDATE_FAILURE']:
        offset = a.find(text.encode()+b'\0')
        assert offset >= 0, text
        labels[text] = {'module_address': hex(0x1101000+offset), 'module_offset': hex(offset)}

    # Четыре участка подготавливают запросы к следующему программному уровню.
    # Для WRITE и DEINIT начало выбрано после отдельного служебного вызова.
    uc = Uc(UC_ARCH_ARM64, UC_MODE_ARM)
    uc.mem_map(0x29AE000, (len(b)+4095)&~4095)
    uc.mem_write(0x29AE000, b)
    uc.mem_protect(0x29AE000, (len(b)+4095)&~4095, UC_PROT_READ | UC_PROT_EXEC)
    uc.mem_map(0x207A000, 0x1000)
    uc.mem_map(0x60000000, 0x1000)
    uc.mem_map(0x70000000, 0x10000)
    pointer, stack = 0x60000000, 0x7000F000
    param = bytes.fromhex('44 33 22 11 88 77 66 55 CC BB AA 99 00 FF EE DD')
    uc.mem_write(pointer, param)
    checks = []
    for label, entry, stop, command, size, expected in [
        ('INIT', 0x2D3C76C, 0x2D3C7A4, 0x600, 16, param[:8]+param[12:16]+param[8:12]),
        ('START', 0x2D3C7B0, 0x2D3C7CC, 0x602, 4, param[:4]),
        ('WRITE', 0x2D3C7F0, 0x2D3C804, 0x603, 4, param[:4]),
        ('DEINIT', 0x2D3C834, 0x2D3C848, 0x601, 4, param[:4]),
    ]:
        uc.reg_write(UC_ARM64_REG_SP, stack)
        uc.reg_write(UC_ARM64_REG_X0, pointer)
        uc.reg_write(UC_ARM64_REG_X19, pointer)
        uc.emu_start(entry, stop, count=200)
        assert uc.reg_read(UC_ARM64_REG_PC) == stop
        assert uc.reg_read(UC_ARM64_REG_X0) == command
        assert uc.reg_read(UC_ARM64_REG_X1) == size
        address = uc.reg_read(UC_ARM64_REG_X2)
        actual = bytes(uc.mem_read(address, size))
        assert actual == expected
        checks.append({'stage': label, 'entry': hex(entry), 'stop_before_call': hex(stop),
                       'command': hex(command), 'payload_bytes': size,
                       'synthetic_payload': actual.hex(' ').upper()})

    dec = zlib.decompressobj(31)
    fs = dec.decompress(decoded[0x42DFDCC:], 64*1024*1024)
    assert dec.eof
    wanted = {'usr/local/bin/emmc-update.sh', 'usr/local/bin/ffsys-emmc-fwver.sh'}
    scripts, pos = {}, 0
    while fs[pos:pos+6] == b'070701':
        h = fs[pos:pos+110]
        fields = [int(h[6+i*8:14+i*8], 16) for i in range(13)]
        nsize, size = fields[11], fields[6]
        name = fs[pos+110:pos+110+nsize-1].decode('utf-8')
        start = (pos+110+nsize+3)&~3
        assert start+size <= len(fs)
        pos = (start+size+3)&~3
        if name == 'TRAILER!!!':
            break
        if name in wanted:
            scripts[name] = fs[start:start+size].decode('utf-8')
    assert set(scripts) == wanted
    assert '/mnt/update/emmc_update.dat' in scripts['usr/local/bin/emmc-update.sh']
    assert '\tsync\n' in scripts['usr/local/bin/emmc-update.sh']

    functions = [
        {'stage': 'INIT', 'handler': '0x02A4EF80', 'helper': '0x02D3C76C',
         'diagnostic': '>> update_init()', 'diagnostic_address': '0x03236100'},
        {'stage': 'START', 'handler': '0x02A4F0E0', 'helper': '0x02D3C7B0',
         'diagnostic': '>> update_start()', 'diagnostic_address': '0x03236118'},
        {'stage': 'WRITE', 'handler': '0x02A4F170', 'helper': '0x02D3C7D8',
         'diagnostic': '>> update_write()', 'diagnostic_address': '0x03236130'},
        {'stage': 'DEINIT', 'handler': '0x02A4EED4', 'helper': '0x02D3C814',
         'diagnostic': '>> update_deinit()', 'diagnostic_address': '0x032360E8'},
    ]
    for f in functions:
        addr = int(f['diagnostic_address'], 16)-0x29AE000
        assert b[addr:addr+len(f['diagnostic'])] == f['diagnostic'].encode()
    result = {
        'date': '2026-11-01', 'source': str(base.SOURCE), 'source_sha256': sha,
        'source_bytes': len(raw), 'version_bytes_at_204': raw[0x204:0x20C].hex(' '),
        'signature': {'verified_on_computer': True, 'algorithm': 'ECDSA',
                      'curve': key.curve.name, 'digest': 'SHA-256',
                      'signature_offset': len(raw)-72, 'signature_bytes': 72,
                      'signed_payload_bytes': len(raw)-72,
                      'camera_verification_call_and_order_not_traced': True},
        'labels': labels, 'handlers_and_helpers': functions,
        'request_preparation_virtual_runs': checks,
        'message_packager': '0x02D3C724', 'message_transport_call': '0x014CF124',
        'linux_scripts_read_only': scripts,
        'source_unchanged': hashlib.sha256(base.SOURCE.read_bytes()).hexdigest() == sha,
        'not_established': [
            'Exact installed updater version in the owners camera',
            'Full path from memory-card file read to nonvolatile-memory controller',
            'Ordering of signature checks, decompression, staging and writes',
            'Physical address map of all installed components',
            'A/B slots, automatic rollback, boot flags or exact power-failure recovery',
            'Whether conditional emmc-update.sh is used in a normal body firmware update',
            'Whether every component is decompressed during installation or during boot',
            'Exact settings and calibration migration rules',
        ],
        'sources': [
            'https://fujifilm-dsc.com/en-int/manual/x-h2/technical_notes/firmware_version/',
            'https://www.fujifilm-x.com/global/support/download/procedure-x-interchangeable-ver2/',
            'https://www.fujifilm-x.com/global/support/download/error-message/',
            'https://www.kingston.com/en/blog/embedded-and-industrial/emmc-lifecycle',
        ],
    }
    assert result['source_unchanged']
    (HERE/'Проверка_этапов_обновления.json').write_text(
        json.dumps(result, ensure_ascii=False, indent=2)+'\n', encoding='utf-8')
    cs = Cs(CS_ARCH_ARM64, CS_MODE_ARM)
    lines = []
    for start, end in [(0x2A4EED4, 0x2A4F254), (0x2D3C724, 0x2D3C85C)]:
        lines.append(f'; {start:#010x} .. {end:#010x}')
        lines.extend(f'{i.address:08X}  {i.bytes.hex(" ").upper():11}  {i.mnemonic:7} {i.op_str}'
                     for i in cs.disasm(b[start-0x29AE000:end-0x29AE000], start))
    (HERE/'Обработчики_и_запросы_обновления.asm').write_text('\n'.join(lines)+'\n', encoding='utf-8')
    print(json.dumps({'signature_verified_on_computer': True, 'source_unchanged': True,
                      'request_preparation_virtual_runs': checks,
                      'script_paths_read': list(scripts)}, ensure_ascii=True, indent=2))


if __name__ == '__main__':
    main()
