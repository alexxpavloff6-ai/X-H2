from pathlib import Path
import hashlib
import json
import re
import struct
import zipfile

from capstone import Cs, CS_ARCH_ARM, CS_MODE_THUMB, CS_MODE_LITTLE_ENDIAN
from unicorn import Uc, UC_ARCH_ARM, UC_MODE_THUMB, UC_HOOK_CODE
from unicorn.arm_const import UC_ARM_REG_PC, UC_ARM_REG_SP, UC_ARM_REG_LR, UC_ARM_REG_R0, UC_ARM_REG_R1

ROOT = Path(__file__).resolve().parents[3]
OUT = Path(__file__).resolve().parent
ZIP = ROOT / 'Firmware на прочиеFuji/Lens/XFUP0019.zip'
CAMERAS = {
    'X-H2 5.30': ROOT / 'FIRMWARE/ver 5.30/FWUP0028.DAT',
    'X-H2S 7.30': ROOT / 'Firmware на прочиеFuji/FWUP0027.DAT',
    'X-T5 4.31': ROOT / 'Firmware на прочиеFuji/FWUP0030.DAT',
    'X100VI 1.31': ROOT / 'Firmware на прочиеFuji/FPUPDATE.DAT',
}

def sha(d):
    return hashlib.sha256(d).hexdigest()

def filehash(p):
    h = hashlib.sha256()
    with p.open('rb') as f:
        for b in iter(lambda: f.read(1024 * 1024), b''):
            h.update(b)
    return h.hexdigest()

def u32(d, o):
    return struct.unpack_from('<I', d, o)[0]

def zstr(d, o):
    if not 0 <= o < len(d):
        return None
    end = d.find(b'\0', o, min(len(d), o + 128))
    if end < 0:
        return None
    return d[o:end].decode('ascii', 'replace')

def occurrences(d, s):
    return [m.start() for m in re.finditer(re.escape(s), d)]

def run_handler(image, entry, flag, initial):
    vm = Uc(UC_ARCH_ARM, UC_MODE_THUMB)
    vm.mem_map(0, 0x80000)
    vm.mem_write(0, image[:0x7f002])
    vm.mem_map(0x20000000, 0x10000)
    vm.mem_write(flag, bytes([initial]))
    vm.reg_write(UC_ARM_REG_SP, 0x2000f000)
    vm.reg_write(UC_ARM_REG_LR, 0x70001)
    trace = []
    call = {}
    def hook(mu, address, size, _):
        if address == 0x33cec:
            fmt = mu.reg_read(UC_ARM_REG_R0)
            call.update({'target': address, 'format_address': fmt,
                         'format': zstr(bytes(mu.mem_read(0, 0x7f002)), fmt),
                         'r1': mu.reg_read(UC_ARM_REG_R1)})
            mu.emu_stop()
            return
        trace.append({'address': address, 'bytes': bytes(mu.mem_read(address, size)).hex()})
    vm.hook_add(UC_HOOK_CODE, hook)
    vm.emu_start(entry | 1, 0x70000, count=40)
    return {'entry': entry, 'flag_address': flag, 'initial': initial,
            'flag_after': bytes(vm.mem_read(flag, 1))[0], 'call_boundary': call,
            'trace': trace, 'limit': 40}

def decode_rx_candidate(image, address, corrupt=False):
    """Restricted RX decoder for this exact instruction family; rejects other bytes."""
    start = 0x45c + ((address - 0xfff80000) & 0xffffffff)
    code = bytearray(image[start:start + 30])
    if corrupt:
        code[0] ^= 1
    # Opcode encodings follow GNU binutils rx-decode.opc; only immediate fields vary.
    shapes = [(0, b'\xfb\xee'), (5, b'\xec\xef\x61\x0f\xfc\xd8\xe0\x60\x80\xe4\xe0\x01\xfb\xee'),
              (22, b'\xe3\x0e\x39'), (27, b'\x62\x80\x02')]
    if any(code[p:p+len(expected)] != expected for p, expected in shapes):
        return {'accepted': False, 'reason': 'unsupported or corrupted opcode sequence', 'bytes': code.hex()}
    def signed24(data):
        n = int.from_bytes(data, 'little')
        return n | 0xff000000 if n & 0x800000 else n
    flag = signed24(code[2:5])
    fmt = signed24(code[19:22])
    displacement = struct.unpack_from('<h', code, 25)[0]
    target = (address + 24 + displacement) & 0xffffffff
    instructions = [
        (0, 5, f'mov.l #{flag:#x}, r14'),
        (5, 2, 'mov.l [r14], r15'),
        (7, 2, 'cmp #0, r15'),
        (9, 3, 'sceq.l [r14]'),
        (12, 2, 'sub #8, r0'),
        (14, 3, 'mov.l [r14], 4[r0]'),
        (17, 5, f'mov.l #{fmt:#x}, r14'),
        (22, 2, 'mov.l r14, [r0]'),
        (24, 3, f'bsr.w {target:#x}'),
        (27, 2, 'add #8, r0'),
        (29, 1, 'rts'),
    ]
    return {'accepted': True, 'entry': address, 'file_offset': start, 'bytes': code.hex(),
            'flag_candidate': flag, 'format_address': fmt, 'signed_branch_displacement': displacement,
            'branch_target': target, 'format_file_offset': 0x45c + ((fmt - 0xfff80000) & 0xffffffff),
            'instructions': [{'address': address + p, 'bytes': code[p:p+n].hex(), 'instruction': desc}
                             for p, n, desc in instructions]}

def run_rx_subset(image, decoded, initial):
    """Isolated interpreter for these decoded RX instructions, halting before bsr."""
    if not decoded['accepted']:
        raise ValueError('undecoded bytes cannot be executed')
    r = {0: 0x001ff000, 14: 0, 15: 0}
    memory = {decoded['flag_candidate']: initial}
    trace = []
    zero = False
    for inst in decoded['instructions']:
        pc = inst['address']
        op = bytes.fromhex(inst['bytes'])
        trace.append(pc)
        if op[:2] == b'\xfb\xee':
            n = int.from_bytes(op[2:], 'little')
            r[14] = n | 0xff000000 if n & 0x800000 else n
        elif op == b'\xec\xef':
            r[15] = memory[r[14]]
        elif op == b'\x61\x0f':
            zero = r[15] == 0
        elif op == b'\xfc\xd8\xe0':
            memory[r[14]] = int(zero)
        elif op == b'\x60\x80':
            r[0] -= 8
        elif op == b'\xe4\xe0\x01':
            memory[r[0] + 4] = memory[r[14]]
        elif op == b'\xe3\x0e':
            memory[r[0]] = r[14]
        elif op[0] == 0x39:
            fmt = memory[r[0]]
            return {'initial': initial, 'flag_after': memory[decoded['flag_candidate']],
                    'stack_pointer': r[0], 'call_boundary': decoded['branch_target'],
                    'stack_word_0_format': fmt,
                    'format': zstr(image, 0x45c + ((fmt - 0xfff80000) & 0xffffffff)),
                    'stack_word_1': memory[r[0] + 4], 'trace': trace,
                    'halt': 'before bsr; callee and return not executed'}
        else:
            raise ValueError(f'unexpected instruction {op.hex()} at {pc:#x}')
    raise ValueError('call boundary not reached')

def main():
    paths = {'archive': ZIP, **CAMERAS}
    before = {k: filehash(p) for k, p in paths.items()}
    result = {'inputs': {k: {'path': str(p.relative_to(ROOT)), 'sha256_before': before[k]} for k, p in paths.items()},
              'scope': 'Whole decompressed DAT members and whole raw camera DAT files; offsets are file offsets unless labelled otherwise.',
              'members': {}, 'camera_ascii': {}, 'vm': [], 'limitations': []}
    with zipfile.ZipFile(ZIP) as z:
        infos = [i for i in z.infolist() if not i.is_dir()]
        data = {i.filename: z.read(i) for i in infos}
        for info in infos:
            d = data[info.filename]
            base = 0 if info.filename.endswith('0019.DAT') else 0xfff80000
            declared = u32(d, 0x270)
            pairs = [{'first': u32(d, 0x278 + 8*i), 'second': u32(d, 0x27c + 8*i)} for i in range(8)]
            markers = [b'FLZNW016', b'LX218A', b'FUJIFILM', b'XF16-55mmF2.8 R LM WR', b'lenscom', b'lensdata', b'mfm\0', b'mim\0', b'mzm\0', b'Monitor Focus Move. Toggle', b'Monitor Iris Move. Toggle', b'Monitor Zoom Move. Toggle', b'focus move monitor = %d', b'iris move monitor = %d', b'zoom move monitor = %d']
            marker_locations = {s.decode('ascii').replace('\0', '\\0'): occurrences(d, s) for s in markers}
            table = 0x5a9e4 if base == 0 else 0x1fb30
            records = []
            for i in range(3):
                pos = table + i * 12
                words = [u32(d, pos + j*4) for j in range(3)]
                mapped = [((v - base) & 0xffffffff) + 0x45c for v in words]
                code_offset = mapped[1] - (words[1] & 1) if base == 0 else mapped[1]
                records.append({'record_file_offset': pos, 'words_le': words,
                                'translated_file_offsets': mapped, 'name': zstr(d, mapped[0]),
                                'description': zstr(d, mapped[2]),
                                'candidate_target_file_offset': code_offset,
                                'target_bytes': d[code_offset:code_offset+32].hex()})
            result['members'][info.filename] = {
                'size': len(d), 'compressed_size': info.compress_size, 'compression_method': info.compress_type,
                'zip_crc32': f'{info.CRC:08x}', 'sha256': sha(d), 'header_u32_le': [u32(d, o) for o in [0, 0x200, 0x204, 0x208, 0x20c, 0x210, 0x240, 0x244, 0x248, 0x270, 0x274]],
                'header_hex_ascii_decoded': bytes.fromhex(d[4:0x200].decode('ascii')).decode('ascii'),
                'declared_region_offset': 0x45c, 'declared_region_length': declared,
                'remaining_bytes': len(d)-0x45c-declared, 'payload_sha256': sha(d[0x45c:0x45c+declared]),
                'trailer_sha256': sha(d[0x45c+declared:]), 'header_eight_candidate_pairs': pairs,
                'hypothetical_linear_base': base, 'markers': marker_locations, 'diagnostic_records': records,
                'elf_magic_offsets': occurrences(d, b'\x7fELF'),
            }
    a, b = [data[i.filename] for i in infos]
    suffix = 0
    for x, y in zip(reversed(a), reversed(b)):
        if x != y:
            break
        suffix += 1
    result['comparison'] = {'common_suffix_length': suffix, 'trailer_equal': a[-156:] == b[-156:],
                            'header_decoded_equal': a[4:0x200] == b[4:0x200]}
    thumb = Cs(CS_ARCH_ARM, CS_MODE_THUMB | CS_MODE_LITTLE_ENDIAN)
    image = a[0x45c:0x45c+u32(a, 0x270)]
    result['thumb_handler_instructions'] = {}
    for name, address, flag in [('mfm', 0x3452c, 0x200090df), ('mim', 0x34504, 0x200090e0), ('mzm', 0x344dc, 0x200090dc)]:
        result['thumb_handler_instructions'][name] = [{'address': x.address, 'bytes': x.bytes.hex(), 'instruction': x.mnemonic + ' ' + x.op_str} for x in thumb.disasm(image[address:address+30], address)]
        for initial in [0, 1, 2]:
            result['vm'].append({'command': name, **run_handler(image, address, flag, initial)})
    rx = {}
    candidates = [('mfm', 0xfffba84d), ('mim', 0xfffba86b), ('mzm', 0xfffba889)]
    for name, addr in candidates:
        decoded = decode_rx_candidate(b, addr)
        offset = decoded['file_offset']
        rx[name] = {'decoded': decoded,
                    'format': zstr(b, decoded['format_file_offset']),
                    'runs': [run_rx_subset(b, decoded, initial) for initial in (0, 1, 2)],
                    'mutated_opcode_negative_control': decode_rx_candidate(b, addr, corrupt=True),
                    'thumb_wrong_alignment_control': [{'address': x.address, 'bytes': x.bytes.hex(),
                         'instruction': x.mnemonic + ' ' + x.op_str}
                         for x in thumb.disasm(b[offset-1:offset+29], addr-1)]}
    entries = [rx[name]['decoded']['bytes'] for name, _ in candidates]
    raw_entries = [bytes.fromhex(x) for x in entries]
    table_word = u32(b, 0x1fb30)
    result['rx0064'] = {
        'reference': 'GNU binutils RX opcode patterns and simulator semantic definitions; restricted independent decoder/interpreter',
        'reference_url': 'https://gnu.googlesource.com/binutils-gdb/+/refs/heads/master/opcodes/rx-decode.opc',
        'execution_model': 'synthetic stack and memory, 32-bit words; stop before bsr, no actual target or hardware',
        'candidates': rx,
        'different_byte_positions_in_30_byte_handlers': [i for i in range(30) if len({x[i] for x in raw_entries}) > 1],
        'alternative_base_controls': [
            {'base': base, 'translated_offset': offset,
             'text': zstr(b, offset), 'expected': 'mfm'}
            for base in (0xfff80000, 0, 0xfff80001)
            for offset in [0x45c + ((table_word - base) & 0xffffffff)]],
        'common_branch_targets': [rx[name]['decoded']['branch_target'] for name, _ in candidates],
    }
    for model, path in CAMERAS.items():
        d = path.read_bytes()
        result['camera_ascii'][model] = {s.decode(): {'raw': {'count': len(raw := occurrences(d, s)), 'first_32_file_offsets': raw[:32]}, 'byte_inverted': {'count': len(inv := occurrences(d, bytes(x ^ 255 for x in s))), 'first_32_file_offsets': inv[:32]}} for s in [b'lenscom', b'lensdata', b'lensdc', b'Monitor Focus Move. Toggle', b'focus move monitor = %d', b'FLZNW016']}
    result['limitations'] = [
        'Address translation is a hypothesis supported by multiple independent table string pointers, not hardware memory map proof.',
        'VM runs only 0019 isolated Thumb diagnostic handlers; synthetic RAM and flags; stops before external call 0x33cec, no real I/O or device.',
        '0064 RX decoding and execution cover only three restricted diagnostic fragments; no specific MCU, complete firmware, actual invocation, physical address map or peripheral is established.',
        'ASCII labels and matching table layouts do not establish physical packets, motion commands, installed versions, hardware compatibility or exchange.',
        'Camera searches cover raw and byte-inverted ASCII substrings in complete DAT, not decompressed FFLZ blocks or proven executable references; no absence inference beyond those ranges and forms.',
    ]
    after = {k: filehash(p) for k, p in paths.items()}
    for k in paths:
        result['inputs'][k]['sha256_after'] = after[k]
        result['inputs'][k]['unchanged'] = after[k] == before[k]
    (OUT / 'результаты.json').write_text(json.dumps(result, ensure_ascii=False, indent=2) + '\n', encoding='utf-8')
    print(json.dumps({'inputs_unchanged': all(v == after[k] for k, v in before.items()),
                      'vm': [{'command': v['command'], 'initial': v['initial'], 'after': v['flag_after'], 'call': v['call_boundary']} for v in result['vm']],
                      'comparison': result['comparison']}, ensure_ascii=False, indent=2))

if __name__ == '__main__':
    main()
