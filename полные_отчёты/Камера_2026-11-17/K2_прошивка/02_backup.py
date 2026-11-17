import json
import sys
from pathlib import Path

HERE = Path(__file__).resolve().parent
sys.path.insert(0, str(HERE.parents[1] / 'Сравнение_версий_2026-11-16'))
import fwcommon

b0 = fwcommon.load('X-H2', 'old', 0)
b1 = fwcommon.load('X-H2', 'old', 1)

checks = [
    (b1, 0x38549B8, 0x2CD1F50, 'GetObjectInfo handler in the operation table'),
    (b1, 0x38549C0, 0x2CD06E0, 'GetObject handler in the operation table'),
    (b1, 0x2CD090C, 0x5000, 'backup object format written for handle 0'),
    (b1, 0x2CD0928, 0x2CDDD94, 'backup transfer started'),
    (b1, 0x2CDDDDC, 0x2CDD284, 'transfer completion callback'),
    (b1, 0x2CD4860, 0xA8, 'X-BACKUP container header added'),
    (b0, 0x115F638, 0x80B9, 'PCSH_EV_SAVE_BACKUPSETTINGS'),
    (b0, 0x115F644, 0x80BA, 'PCSH_EV_LOAD_BACKUPSETTINGS'),
    (b1, 0x2C0E53C, 0x2BF2DD0, 'save event handler'),
    (b1, 0x2C0E3A8, 0x2BF2E5C, 'load event handler'),
    (b0, 0x1133A0C, 0x12E5B44, 'backup serialization entry'),
    (b0, 0x11DA71C, 0x12768, 'UI settings bank copy size'),
    (b0, 0x12E5B64, 0x11DA714, 'copy function used by serialization'),
    (b0, 0x12E5B6C, 0x12E5AD4, 'backup-specific transformations'),
    (b1, 0x2BF2DEC, 0x1133A04, 'main segment producer'),
    (b1, 0x2BF2DF4, 0xF6D4, 'main segment length in the save message'),
    (b1, 0x2BF2DFC, 0x1133A18, 'custom segment producer'),
    (b1, 0x2BF2E04, 0x1C00, 'custom segment length in the save message'),
    (b0, 0x12DC5D8, 0x2588000, 'custom segment RAM page'),
    (b0, 0x12DC604, 0x1F4, 'custom segment RAM pointer low offset'),
    (b0, 0x12E5E34, 0x3C, 'checksum field loaded by validator'),
    (b0, 0x12E5E38, 0x3C, 'checksum field zeroed by validator'),
    (b1, 0x2CCE0E4, 0x8, 'X-BACKUP copied at header+8'),
    (b1, 0x2CCE0F8, 0x10, '0100 copied at header+0x10'),
]
rows = []
for block, address, expected, name in checks:
    if address in (0x38549B8, 0x38549C0):
        value = block.u32(address)
        ok = value == expected
        actual = hex(value)
    elif expected == 0x12768:
        instructions = fwcommon.insns(block, address, 2)
        actual = ' | '.join(f'{insn.mnemonic} {insn.op_str}' for insn in instructions)
        ok = (instructions[0].mnemonic == 'mov' and instructions[0].op_str == 'w2, #0x2768'
              and instructions[1].mnemonic == 'movk' and instructions[1].op_str == 'w2, #1, lsl #16')
    else:
        instruction = fwcommon.insns(block, address, 1)[0]
        needle = f'#0x{expected:x}'
        ok = (needle in instruction.op_str
              or (expected == 0x2CDD284 and instruction.op_str == 'x0, x0, #0x284')
              or (address == 0x2CCE0E4 and instruction.op_str == 'x0, x20, #8'))
        actual = f'{instruction.mnemonic} {instruction.op_str}'
    rows.append({'block': block.idx, 'address': hex(address), 'expected': hex(expected), 'actual': actual, 'ok': ok, 'name': name})
assert all(row['ok'] for row in rows), [row for row in rows if not row['ok']]

assert b1.cstr(0x33B0C98) == 'X-BACKUP'
assert b1.cstr(0x33B0CA8) == '0100'
assert b1.cstr(0x33B0E88) == 'PCSH_BACKUP_TXBUF_OVER'
checksum_start = 0x2578A20
checksum_end = 0x2578A18 + 0xF000 + 0x675
assert checksum_end - checksum_start == 0xF66D
assert 0xF6D4 + 0x1C00 == 0x112D4
assert 0x112D4 + 0xA8 == 0x1137C

result = {
    'firmware': 'X-H2 5.30',
    'ptp_export': {
        'sequence': ['0x1008 GetObjectInfo(handle=0)', '0x1009 GetObject(handle=0)'],
        'direction': 'camera to host',
        'object_format': '0x5000 (FujiBackup)',
        'external_proof': 'https://github.com/karaolidis/fujicli/blob/main/crates/fujicore/src/features/backup/manager.rs',
        'firmware_handlers': {'get_object_info': '0x2CD1F50', 'get_object': '0x2CD06E0'},
        'get_object_backup_path': ['0x2CD0904', '0x2CD090C', '0x2CD0918', '0x2CD0928'],
        'container_magic': 'X-BACKUP0100',
        'magic_builder': '0x2CCE0C0',
        'magic_file_offset': 8,
        'container_header_bytes': '0xA8',
    },
    'restore_write_only': {
        'sequence': ['0x100C SendObjectInfo', '0x100D SendObject'],
        'event': 'PCSH_EV_LOAD_BACKUPSETTINGS=0x80BA',
        'handler': '0x2BF2E5C',
        'note': 'Not used and not approved for this task.',
    },
    'serialization': {
        'save_event': 'PCSH_EV_SAVE_BACKUPSETTINGS=0x80B9',
        'handler_chain': ['0x2C0E538', '0x2BF2DD0', '0x1133A04', '0x12E5B44', '0x11DA714'],
        'source_bank': '0x2628A88', 'destination_bank': '0x2578A18', 'bank_copy_bytes': '0x12768',
        'transform_function': '0x12E5AD4',
        'segments': {
            'main': {'producer': '0x1133A04', 'bytes': '0xF6D4', 'raw_range': [0, 0xF6D4], 'bank_range': [8, 0xF6DC]},
            'custom': {'producer': '0x1133A18', 'bytes': '0x1C00', 'raw_range': [0xF6D4, 0x112D4],
                       'bank_range': [0xF7DC, 0x113DC], 'ram_buffer': '0x25881F4', 'slots': '7 x 0x400'},
        },
        'combined_payload_bytes': '0x112D4', 'with_container_bytes': '0x1137C',
        'offset_formulas': {'main': 'raw=bank-8', 'custom': 'raw=bank-0x108', 'container': 'file=raw+0xA8'},
        'checksum_first_span': {'start': hex(checksum_start), 'end_exclusive': hex(checksum_end), 'bytes': '0xF66D'},
        'checksum_destination': '0x2578A5C', 'checksum_raw_offset': '0x3C',
        'checksum_validator': '0x12E5D9C: zero raw+0x3C, then sum bytes; custom segment is added by 0x12DC5CC',
        'returned_main_buffer': '0x2578A20', 'returned_custom_buffer': '0x25881F4',
        'warning': '0x12768 is the source-bank copy size, not the file size. Only the two listed bank ranges are exported. Other accepted restore lengths are compatibility variants, not this save-message layout.',
    },
    'record_0x4c_inclusion': {
        'status': 'not_observed_in_real_01_02',
        'direct_record_rpc_in_identified_export_path': False,
        'full_signature_in_required_blobs': False,
        'unexplained_changed_bytes': 0,
        'reason': 'The export path copies and transforms two UI-bank ranges without record RPC. Real 01/02 blobs contain no record 0x4C signature; all 27 changed bytes are assigned to UI fields, checksum or volatile service metadata.',
        'remaining_caveat': 'A separate service-projected scalar without a record header cannot be excluded statically, but no MOVDC guard candidate is observed. Use RAM/record-service snapshots for the flag.',
        'verification_script': '08_проверка_реальных.py',
        'proof_artifacts': ['реальные_блобы.json', 'реальный_diff.tsv'],
    },
    'checks': rows,
}
lines = [
    'BACKUP export: 0x1008 GetObjectInfo(0) then 0x1009 GetObject(0), object format 0x5000, camera→host.',
    'Restore: 0x100C/0x100D, not used.',
    'Save chain: 0x80B9 → 0x2C0E538 → 0x2BF2DD0 → 0x1133A04 → 0x12E5B44 → 0x11DA714.',
    'Bank copy: 0x2628A88 → 0x2578A18, 0x12768 bytes + backup transformations; only two ranges are exported.',
    'Export segments: main 0xF6D4 (bank 8..0xF6DC) + custom 0x1C00 (bank 0xF7DC..0x113DC) = 0x112D4.',
    'Offsets: main raw=bank-8; custom raw=bank-0x108; container file=raw+0xA8; expected container total 0x1137C.',
    'Checksum: validator 0x12E5D9C zeroes raw+0x3C and sums the defined spans; custom segment is included.',
    'Container: X-BACKUP0100 at header+8, header size 0xA8.',
    'Record 0x4C: NOT OBSERVED in real 01/02. No signature; 27/27 changed bytes explained; no guard candidate.',
]
(HERE / 'backup.txt').write_text('\n'.join(lines) + '\n', encoding='utf-8')
(HERE / 'backup.json').write_text(json.dumps(result, ensure_ascii=False, indent=2) + '\n', encoding='utf-8')
print(f'OK: {len(rows)} BACKUP checks; two-segment layout verified; record 0x4C not observed in real blobs')
