import json
import re
import sys
from pathlib import Path

HERE = Path(__file__).resolve().parent
sys.path.insert(0, str(HERE.parents[1] / 'Сравнение_версий_2026-11-16'))
sys.path.insert(0, str(HERE.parents[1] / 'Сравнение_версий_2026-11-16/A_LCD_MOVDC'))
import fwcommon
from fwemu import scan_address

getter = 0x14CF354
rpc_wrapper = 0x14CF45C
state_bit_api = 0x12E8814
calls = []
for block_index in (0, 1, 2):
    block = fwcommon.load('X-H2', 'old', block_index)
    for target, role in ((getter, 'record_get'), (rpc_wrapper, 'record_rpc'), (state_bit_api, 'state_bit')):
        for site, branch in fwcommon.bl_callers(block, target):
            instructions = fwcommon.insns(block, site - 0x14, 6)
            if any(re.fullmatch(r'mov(z)? w0, #0x4c', insn.mnemonic + ' ' + insn.op_str) for insn in instructions):
                calls.append({
                    'block': block_index,
                    'site': hex(site),
                    'branch': branch,
                    'role': role,
                    'target': hex(target),
                    'context': fwcommon.dis(block, site - 0x14, 6),
                })

record_calls = [row for row in calls if row['role'] == 'record_get']
assert len(record_calls) == 1
assert record_calls[0]['site'] == '0x31053f8'
assert not [row for row in calls if row['role'] == 'record_rpc']
state_bit_calls = [row for row in calls if row['role'] == 'state_bit']
assert state_bit_calls

references = {}
for address, name in ((0x4C3F104, 'pending_flag'), (0x4C3F26C, 'current_flag'), (0x4C33F14, 'state_flag')):
    references[name] = {}
    for block_index in (0, 1, 2):
        references[name][f'block{block_index}'] = scan_address('X-H2', 'old', block_index, address)
assert not references['pending_flag']['block0']
assert not references['pending_flag']['block1']
assert not references['pending_flag']['block2']
assert len(references['current_flag']['block1']) == 2
assert all(row['kind'] == 'r' for row in references['current_flag']['block1'])
state_writes = [row for row in references['state_flag']['block1'] if row['kind'] == 'w']
assert sorted(row['va'] for row in state_writes) == ['0x31085a8', '0x3108aa8']

result = {
    'firmware': 'X-H2 5.30',
    'direct_static_link_to_scenario': False,
    'evidence': {
        'record_get_calls_with_id_0x4c': record_calls,
        'record_rpc_calls_with_id_0x4c': [],
        'state_bit_calls_with_id_0x4c_count': len(state_bit_calls),
        'state_bit_examples': state_bit_calls[:4],
        'state_bit_api': {
            'address': '0x12E8814',
            'meaning': 'Reads a bit from the separate state-bit table at 0x26A70A8 + 0x43A0 + 4*index; it does not read or write record 0x4C.',
        },
        'memory_references': references,
    },
    'conclusion': 'No writer of record 0x4C/payload+0x64 is visible in blocks 0-2. The only record read is 0x31053F8. The only flag writes are the two apply copies 0x31085A8 and 0x3108AA8 from current+0x74 to state+0x43C. Drive/SHUTTER TYPE/SHUTTER SPEED/IMAGE DISP cannot be statically linked to the record in this firmware.',
    'snapshot_expectations': {
        'record_id': '0x4C',
        'payload_expected_bytes': '0x158 (inferred from 0x168 RAM container minus 0x10 header+pointer; runtime size comes from the service)',
        'flag': 'unsigned 32-bit little-endian at payload+0x64',
        'pending': {'container': '0x4C3F090', 'payload': '0x4C3F0A0', 'flag': '0x4C3F104'},
        'current': {'container': '0x4C3F1F8', 'payload': '0x4C3F208', 'flag': '0x4C3F26C'},
        'state_flag': '0x4C33F14',
        'ram_container_flag_offset': '0x74',
        'serialized_8byte_header_flag_offset': '0x6C',
        'record_signature_if_size_matches': '4c 00 ?? ?? 58 01 00 00',
        'backup_warning': 'Do not assume that a BACKUP blob uses the runtime 16-byte container or that record 0x4C is present. First diff whole blobs; only then test candidate signatures and offsets.',
        'candidate_change': 'A 4-byte little-endian transition unique to CH+ES+<=1/8000+CONTINUOUS relative to S, MS, 1/250 and DISP OFF, with a repeat-baseline control. No particular value is guaranteed by static code; 0 and 1 are candidates, not a prediction.',
    },
}

lines = [
    result['conclusion'],
    '',
    f"record get calls with id 0x4C: {len(record_calls)} (0x31053F8)",
    'record RPC calls with id 0x4C: 0',
    f"state-bit calls with id 0x4C: {len(state_bit_calls)} (different API 0x12E8814)",
    'pending+0x74 writes: 0 in blocks 0-2',
    'current+0x74: only two reads (0x31085A4, 0x3108AA4)',
    'state flag writes: 0x31085A8 and 0x3108AA8',
    '',
    'K1: flag = u32 LE at record payload+0x64; pending 0x4C3F104; current 0x4C3F26C; state 0x4C33F14.',
    'RAM container+0x74; if serialized with only the 8-byte record header, offset+0x6C.',
    'Expected payload 0x158; signature 4c 00 ?? ?? 58 01 00 00 if the service uses that size.',
    'Diff the entire BACKUP blob; do not assume inclusion or a fixed offset.',
]
(HERE / 'связь_0x4c.txt').write_text('\n'.join(lines) + '\n', encoding='utf-8')
(HERE / 'связь_0x4c.json').write_text(json.dumps(result, ensure_ascii=False, indent=2) + '\n', encoding='utf-8')
print(f'OK: 1 record read, 0 record writes, {len(state_bit_calls)} unrelated state-bit calls; saved связь_0x4c.txt/.json')
