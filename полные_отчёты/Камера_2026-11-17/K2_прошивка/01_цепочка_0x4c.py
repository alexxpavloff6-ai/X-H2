import json
import sys
from pathlib import Path

HERE = Path(__file__).resolve().parent
sys.path.insert(0, str(HERE.parents[1] / 'Сравнение_версий_2026-11-16'))
import fwcommon

b0 = fwcommon.load('X-H2', 'old', 0)
b1 = fwcommon.load('X-H2', 'old', 1)
b2 = fwcommon.load('X-H2', 'old', 2)

checks = [
    ('геттер записей: вход', b0, 0x14CF354, 'stp', 'x29, x30, [sp, #-0x40]!'),
    ('геттер: resolve(id)', b0, 0x14CF374, 'bl', '#0x5460c'),
    ('геттер: копирование payload', b0, 0x14CF3FC, 'bl', '#0x14d2534'),
    ('RPC wrapper: вход', b0, 0x14CF45C, 'stp', 'x29, x30, [sp, #-0x50]!'),
    ('RPC: тип запроса 2', b0, 0x14CF4AC, 'mov', 'w1, #2'),
    ('RPC: ptr', b0, 0x14CF4B4, 'str', 'x2, [sp, #0x38]'),
    ('RPC: id, первое поле', b0, 0x14CF4BC, 'str', 'x0, [sp, #0x40]'),
    ('RPC: id, второе поле', b0, 0x14CF4C0, 'str', 'x0, [sp, #0x48]'),
    ('RPC: вызов сервиса', b0, 0x14CF4C8, 'bl', '#0x4a458'),
    ('get_record: id=0x4C', b1, 0x31053F4, 'mov', 'w0, #0x4c'),
    ('get_record: вызов', b1, 0x31053F8, 'bl', '#0x14cf354'),
    ('memcpy: размер контейнера', b1, 0x3105448, 'mov', 'w2, #0x168'),
    ('memcpy: pending page', b1, 0x310544C, 'adrp', 'x1, #0x4c3f000'),
    ('memcpy: pending offset', b1, 0x3105450, 'add', 'x1, x1, #0x90'),
    ('memcpy: current page', b1, 0x3105454, 'adrp', 'x0, #0x4c3f000'),
    ('memcpy: current offset', b1, 0x3105458, 'add', 'x0, x0, #0x1f8'),
    ('memcpy: вызов', b1, 0x310545C, 'bl', '#0x153ce8c'),
    ('apply1: вход', b1, 0x3108494, 'stp', 'x29, x30, [sp, #-0x20]!'),
    ('apply1: memcpy pending→current', b1, 0x31084A0, 'bl', '#0x3105440'),
    ('apply1: current+0x74', b1, 0x31085A4, 'ldr', 'w2, [x1, #0x1e4]'),
    ('apply1: state+0x43C', b1, 0x31085A8, 'str', 'w2, [x0, #0x43c]'),
    ('apply2: вход', b1, 0x31089B8, 'stp', 'x29, x30, [sp, #-0x20]!'),
    ('apply2: memcpy pending→current', b1, 0x31089C0, 'bl', '#0x3105440'),
    ('apply2: current+0x74', b1, 0x3108AA4, 'ldr', 'w2, [x1, #0x1e4]'),
    ('apply2: state+0x43C', b1, 0x3108AA8, 'str', 'w2, [x0, #0x43c]'),
    ('apply2: MOVDC', b1, 0x3108AF0, 'bl', '#0x3107e84'),
    ('MOVDC: вход', b1, 0x3107E84, 'sub', 'sp, sp, #0x2a0'),
    ('MOVDC: дескриптор', b1, 0x3108090, 'ldr', 'x0, [x0, #0xf60]'),
    ('MOVDC: наследование stride, без guard 5.33', b1, 0x31080A0, 'ldr', 'w0, [x0, #8]'),
    ('MOVDC: сдвиг stride', b1, 0x31080A4, 'lsr', 'w0, w0, #1'),
    ('MOVDC: сохранение половины stride', b1, 0x31080A8, 'str', 'w0, [sp, #0x16c]'),
    ('MOVDC: чтение флага позже наследования', b1, 0x31080F8, 'ldr', 'w0, [x0, #0xf14]'),
    ('MOVDC: запись out+8', b1, 0x3108150, 'str', 'w0, [x1, #8]'),
    ('сервисный вход 0x4A458 в block2', b2, 0x4A458, 'add', 'x0, x0, #0x18, lsl #12'),
]

rows = []
for name, block, address, mnemonic, operands in checks:
    insn = fwcommon.insns(block, address, 1)[0]
    ok = insn.mnemonic == mnemonic and insn.op_str == operands
    rows.append({
        'name': name,
        'block': block.idx,
        'address': hex(address),
        'bytes': insn.bytes.hex(),
        'instruction': f'{insn.mnemonic} {insn.op_str}',
        'expected': f'{mnemonic} {operands}',
        'ok': ok,
    })

assert all(row['ok'] for row in rows), [row for row in rows if not row['ok']]

result = {
    'firmware': 'X-H2 5.30',
    'all_checks_passed': True,
    'addresses': {
        'record_getter': '0x14CF354',
        'record_rpc_wrapper': '0x14CF45C',
        'record_rpc_service_entry': '0x4A458',
        'get_record_id_instruction': '0x31053F4',
        'get_record_call': '0x31053F8',
        'pending_to_current_memcpy_function': '0x3105440',
        'apply1_function': '0x3108494',
        'apply1_flag_write': '0x31085A8',
        'apply2_function': '0x31089B8',
        'apply2_flag_write': '0x3108AA8',
        'movdc_function': '0x3107E84',
        'state_base': '0x4C33AD8',
        'state_flag': '0x4C33F14',
        'pending_container': '0x4C3F090',
        'pending_payload': '0x4C3F0A0',
        'pending_flag': '0x4C3F104',
        'current_container': '0x4C3F1F8',
        'current_payload': '0x4C3F208',
        'current_flag': '0x4C3F26C',
    },
    'layout': {
        'ram_container_bytes': 0x168,
        'record_header_and_pointer_bytes': 0x10,
        'expected_service_payload_bytes': 0x158,
        'flag_width_bytes': 4,
        'flag_offset_in_container': 0x74,
        'flag_offset_in_payload': 0x64,
        'byte_order': 'little-endian',
        'note': '0x158 follows from the container layout; the runtime record size is supplied by the service.',
    },
    'service_entry_note': '0x4A458 is an alternate/service entry inside the block2 routine, not a normal standalone function prologue; the direct BL from the block0 RPC wrapper is the primary evidence.',
    'checks': rows,
}

lines = []
for row in rows:
    lines.append(f"{row['address']} b{row['block']}  {row['bytes']:<10} {row['instruction']:<40} ; {row['name']}")
lines.extend([
    '',
    'pending container 0x4C3F090; payload 0x4C3F0A0; flag container+0x74=payload+0x64=0x4C3F104',
    'current container 0x4C3F1F8; payload 0x4C3F208; flag container+0x74=payload+0x64=0x4C3F26C',
    'state 0x4C33AD8; flag state+0x43C=0x4C33F14',
    'RAM container=0x168; header+pointer=0x10; expected service payload=0x158; flag=u32 LE',
    '0x4A458 is a service/alternate entry, not a normal standalone prologue.',
])
(HERE / 'цепочка_0x4c.txt').write_text('\n'.join(lines) + '\n', encoding='utf-8')
(HERE / 'цепочка_0x4c.json').write_text(json.dumps(result, ensure_ascii=False, indent=2) + '\n', encoding='utf-8')
print(f'OK: {len(rows)} instruction checks; saved цепочка_0x4c.txt/.json')
