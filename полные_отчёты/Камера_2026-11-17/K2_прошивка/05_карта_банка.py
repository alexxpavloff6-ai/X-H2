import csv
import json
import re
import struct
import sys
from collections import defaultdict
from pathlib import Path

HERE = Path(__file__).resolve().parent
ROOT = HERE.parents[2]
sys.path.insert(0, str(HERE.parents[1] / 'Сравнение_версий_2026-11-16'))
import fwcommon

GETTER = 0x12AA788
CASE_BASE = 0x12AA7DC
OFFSET_TABLE = 0x174EE70
SETTINGS = 0x2628A88
BANK_SIZE = 0x12768
BANK_TO_BLOB = -8
CONTAINER_SIZE = 0xA8
ID_COUNT = 0xD6A

b0 = fwcommon.load('X-H2', 'old', 0)
catalog_path = ROOT / 'Внешние_репозитории/fujimod/catalog/firmware/xh2/5.30/ui-setting-names.generated.json'
catalog = json.loads(catalog_path.read_text(encoding='utf-8'))
assert catalog['firmware_id'] == 'xh2-530'
ui_names = catalog['ui_setting_names']
names_by_id = defaultdict(list)
for name, setting_id in ui_names.items():
    names_by_id[setting_id].append(name)


def operands(insn):
    result, start, depth = [], 0, 0
    for index, char in enumerate(insn.op_str):
        if char in '[(':
            depth += 1
        elif char in '])':
            depth -= 1
        elif char == ',' and depth == 0:
            result.append(insn.op_str[start:index].strip())
            start = index + 1
    result.append(insn.op_str[start:].strip())
    return result


def immediate(text):
    match = re.fullmatch(r'#(-?(?:0x[0-9a-f]+|\d+))', text)
    return int(match.group(1), 0) if match else None


def shifted_immediate(parts):
    value = immediate(parts[0])
    if value is None:
        return None
    if len(parts) > 1:
        match = re.fullmatch(r'lsl #(\d+)', parts[1])
        if not match:
            return None
        value <<= int(match.group(1))
    return value


def register_value(name, registers):
    if name in ('xzr', 'wzr'):
        return 0
    canonical = 'x' + name[1:] if name.startswith('w') and name[1:].isdigit() else name
    if canonical not in registers:
        return None
    value = registers[canonical]
    if value is None:
        return None
    return value & 0xFFFFFFFF if name.startswith('w') else value


def put_register(name, value, registers):
    if name in ('xzr', 'wzr'):
        return
    canonical = 'x' + name[1:] if name.startswith('w') and name[1:].isdigit() else name
    if value is not None and name.startswith('w'):
        value &= 0xFFFFFFFF
    registers[canonical] = value


def memory_address(text, registers):
    match = re.fullmatch(r'\[([^]]+)\](?:, #(?:0x[0-9a-f]+|\d+))?', text)
    if not match:
        return None
    parts = [part.strip() for part in match.group(1).split(', ')]
    if not parts:
        return None
    value = register_value(parts[0], registers)
    if value is None:
        return None
    if len(parts) >= 2:
        offset = immediate(parts[1])
        if offset is None and parts[1] in registers:
            offset = register_value(parts[1], registers)
            if offset is not None and len(parts) >= 3:
                extension = re.fullmatch(r'(sxtw|uxtw|sxtx|lsl)(?: #(\d+))?', parts[2])
                if not extension:
                    return None
                if extension.group(1) == 'sxtw':
                    offset &= 0xFFFFFFFF
                    if offset & 0x80000000:
                        offset -= 1 << 32
                elif extension.group(1) == 'uxtw':
                    offset &= 0xFFFFFFFF
                if extension.group(2):
                    offset <<= int(extension.group(2))
        if offset is None:
            return None
        value += offset
    return value


def setting_names(setting_id):
    names = names_by_id[setting_id]
    return {
        'name': names[0] if names else f'UI_SETP_0x{setting_id:X}',
        'all_names': names,
        'bkup_names': [name for name in names if 'BKUP' in name],
    }


def scan_case(setting_id, case, mode=0, custom_slot=0):
    registers = {f'x{i}': None for i in range(31)}
    registers.update({f'w{i}': None for i in range(31)})
    registers.update({'x19': custom_slot, 'w19': custom_slot, 'x20': 0, 'w20': 0,
                      'x21': setting_id, 'w21': setting_id,
                      'x22': 0, 'w22': 0, 'x23': mode, 'w23': mode})
    hits = []
    dynamic_index = False
    last_compare = None
    instructions = fwcommon.insns(b0, case, 90)
    targets = {insn.address: index for index, insn in enumerate(instructions)}
    index = 0
    while index < len(instructions):
        insn = instructions[index]
        index += 1
        op = operands(insn)
        mnemonic = insn.mnemonic
        if mnemonic == 'cmp' and len(op) == 2:
            last_compare = (op[0], immediate(op[1]))
        elif mnemonic in ('b.eq', 'b.ne') and last_compare and last_compare[0] in ('w19', 'w20', 'w22', 'w23'):
            register, expected = last_compare
            equal = register_value(register, registers) == expected
            if (mnemonic == 'b.eq') == equal:
                target = int(op[0][1:], 0)
                if target not in targets:
                    break
                index = targets[target]
                continue
        if mnemonic in ('ldrb', 'ldrh', 'ldr', 'ldrsb', 'ldrsh', 'ldrsw') and len(op) >= 2:
            address = memory_address(op[1], registers)
            size = 1 if mnemonic in ('ldrb', 'ldrsb') else 2 if mnemonic in ('ldrh', 'ldrsh') else 4
            if mnemonic == 'ldr' and op[0].startswith('x'):
                size = 8
            if address is not None and SETTINGS <= address and address + size <= SETTINGS + BANK_SIZE:
                bank_offset = address - SETTINGS
                hits.append({
                    'bank_offset': bank_offset,
                    'blob_offset': bank_offset + BANK_TO_BLOB,
                    'container_offset': bank_offset + BANK_TO_BLOB + CONTAINER_SIZE,
                    'size': size,
                    'type': f'u{size * 8}',
                    'signed_access': mnemonic.startswith('ldrs'),
                    'instruction_address': insn.address,
                    'instruction': f'{insn.mnemonic} {insn.op_str}',
                    'dynamic_index_assumed_zero': dynamic_index,
                })
            put_register(op[0], 0, registers)
            dynamic_index = True
        elif mnemonic in ('adrp', 'adr') and len(op) == 2:
            put_register(op[0], immediate(op[1]), registers)
        elif mnemonic in ('mov', 'movz') and len(op) >= 2:
            value = register_value(op[1], registers)
            if value is None:
                value = shifted_immediate(op[1:])
            put_register(op[0], value, registers)
        elif mnemonic == 'movk' and len(op) >= 2:
            value = immediate(op[1])
            old = register_value(op[0], registers)
            if value is None or old is None:
                put_register(op[0], None, registers)
            else:
                shift = 0
                if len(op) >= 3:
                    match = re.fullmatch(r'lsl #(\d+)', op[2])
                    if not match:
                        put_register(op[0], None, registers)
                        continue
                    shift = int(match.group(1))
                mask = 0xFFFF << shift
                put_register(op[0], (old & ~mask) | (value << shift), registers)
        elif mnemonic == 'movn' and len(op) >= 2:
            value = shifted_immediate(op[1:])
            put_register(op[0], ~value if value is not None else None, registers)
        elif mnemonic in ('add', 'sub') and len(op) >= 3:
            left = register_value(op[1], registers)
            right = register_value(op[2], registers)
            if right is None:
                right = shifted_immediate(op[2:])
            if left is None or right is None:
                value = None
            else:
                value = left + right if mnemonic == 'add' else left - right
            put_register(op[0], value, registers)
        elif mnemonic == 'madd' and len(op) == 4:
            values = [register_value(part, registers) for part in op[1:]]
            put_register(op[0], values[0] * values[1] + values[2] if all(v is not None for v in values) else None, registers)
        elif mnemonic == 'mul' and len(op) == 3:
            values = [register_value(part, registers) for part in op[1:]]
            put_register(op[0], values[0] * values[1] if all(v is not None for v in values) else None, registers)
        elif mnemonic == 'ubfiz' and len(op) == 4:
            source = register_value(op[1], registers)
            shift, width = immediate(op[2]), immediate(op[3])
            put_register(op[0], (source & ((1 << width) - 1)) << shift if source is not None and shift is not None and width is not None else None, registers)
        elif mnemonic in ('lsl', 'lsr') and len(op) == 3:
            source, amount = register_value(op[1], registers), immediate(op[2])
            if source is None or amount is None:
                value = None
            else:
                value = source << amount if mnemonic == 'lsl' else source >> amount
            put_register(op[0], value, registers)
        elif mnemonic in ('b', 'br', 'blr', 'bl', 'ret'):
            break
    return hits


def serialized_offset(bank_offset):
    if 8 <= bank_offset < 0xF6DC:
        return bank_offset - 8, 'main_0xF6D4'
    if 0xF7DC <= bank_offset < 0x113DC:
        return bank_offset - 0x108, 'custom_0x1C00'
    return None, 'outside_exported_segments'


def optional_hex(value):
    return f'0x{value:X}' if value is not None else None


def make_entry(setting_id, case, hits, mode):
    if not hits:
        return None
    primary = hits[0]
    evidence = []
    for hit in hits:
        raw_offset, segment = serialized_offset(hit['bank_offset'])
        evidence.append({
            'bank_offset': f"0x{hit['bank_offset']:X}",
            'blob_offset': optional_hex(raw_offset),
            'container_offset': optional_hex(raw_offset + CONTAINER_SIZE if raw_offset is not None else None),
            'segment': segment,
            'size': hit['size'], 'type': hit['type'], 'signed_access': hit['signed_access'],
            'instruction_address': f"0x{hit['instruction_address']:X}", 'instruction': hit['instruction'],
            'dynamic_index_assumed_zero': hit['dynamic_index_assumed_zero'],
        })
    raw_offset, segment = serialized_offset(primary['bank_offset'])
    return {'id': setting_id, 'ui_setp': f'0x{setting_id:X}', 'case': f'0x{case:X}', **setting_names(setting_id),
            'layout_mode': mode, 'bank_offset': f"0x{primary['bank_offset']:X}",
            'blob_offset': optional_hex(raw_offset),
            'container_offset': optional_hex(raw_offset + CONTAINER_SIZE if raw_offset is not None else None),
            'segment': segment, 'size': primary['size'], 'type': primary['type'],
            'signed_access': primary['signed_access'], 'instruction_address': f"0x{primary['instruction_address']:X}",
            'instruction': primary['instruction'], 'evidence': evidence}


entries_by_mode = {0: [], 1: []}
current_by_mode = {0: [], 1: []}
without_field = []
for setting_id in range(1, ID_COUNT + 1):
    signed_offset = struct.unpack_from('<i', b0.data, b0.off(OFFSET_TABLE) + 4 * (setting_id - 1))[0]
    case = CASE_BASE + 4 * signed_offset
    made = False
    for custom_slot, destination in ((0, entries_by_mode), (7, current_by_mode)):
        for mode in (0, 1):
            entry = make_entry(setting_id, case, scan_case(setting_id, case, mode, custom_slot), mode)
            if entry:
                entry['custom_slot'] = custom_slot
                entry['selector_mode'] = mode
                destination[mode].append(entry)
                made = True
    if not made:
        without_field.append({'id': setting_id, 'ui_setp': f'0x{setting_id:X}', 'case': f'0x{case:X}', **setting_names(setting_id),
                              'reason': 'No direct load from the UI settings bank on slot-0 or current slot-7 getter paths; dynamic/fallback handling is possible.'})


def layout_signature(entries):
    return {entry['id']: (entry['bank_offset'], entry['size'], entry['instruction_address']) for entry in entries}


assert layout_signature(current_by_mode[0]) == layout_signature(current_by_mode[1])
entries = current_by_mode[0]
for entry in entries:
    entry['layout_mode'] = 'current'
entries_mode1 = entries_by_mode[1]
by_id = {entry['id']: entry for entry in entries}
mode0_by_id = {entry['id']: entry for entry in entries_by_mode[0]}
mode1_by_id = {entry['id']: entry for entry in entries_mode1}

expected_legacy = {
    0x858: (0x1168C, 0x12BA3D0, 0x12BA414, 1),
    0x827: (0x11719, 0x12C5FC4, 0x12C6008, 1),
    0xB: (0x1FB, 0x12AA8A4, 0x12AA8C4, 1),
    0x2B9: (0x1144, None, None, None),
    0x979: (0x5A0, None, None, None),
    0xD: (0x202, None, None, None),
}
for setting_id, (offset, case, instruction, size) in expected_legacy.items():
    entry = mode0_by_id[setting_id]
    assert int(entry['bank_offset'], 0) == offset, entry
    if case is not None:
        assert int(entry['case'], 0) == case, entry
        assert int(entry['instruction_address'], 0) == instruction, entry
        assert entry['size'] == size, entry
for setting_id in (0x89E, 0x991, 0x833):
    assert setting_id not in by_id
    assert int(next(row['case'] for row in without_field if row['id'] == setting_id), 0) == 0x12D27E8

assert by_id[1]['name'] == 'UI_SETP_BKUP_VER'
assert int(by_id[1]['bank_offset'], 0) == 0x1F8
assert mode0_by_id[0x858]['blob_offset'] is None
assert mode0_by_id[0x827]['blob_offset'] is None
for setting_id, bank_offset, raw_offset, instruction in ((0x858, 0xF8F0, 0xF7E8, 0x12BA458),
                                                         (0x827, 0xF97D, 0xF875, 0x12C604C),
                                                         (0xB, 0x1FB, 0x1F3, 0x12AA8C4)):
    entry = mode1_by_id[setting_id]
    assert int(entry['bank_offset'], 0) == bank_offset, entry
    assert int(entry['blob_offset'], 0) == raw_offset, entry
    assert int(entry['instruction_address'], 0) == instruction, entry
    assert entry['size'] == 1, entry

current_expected = {
    0x858: (0x458, 0x450, 0x4F8, 0x12BA480, 1),
    0x827: (0x59A, 0x592, 0x63A, 0x12C6074, 1),
    0xB: (0x1FB, 0x1F3, 0x29B, 0x12AA8C4, 1),
    0x8A0: (0x512, 0x50A, 0x5B2, 0x12C1F84, 1),
    0x8A9: (0x20, 0x18, 0xC0, 0x12C2340, 4),
    0x874: (0x42D, 0x425, 0x4CD, 0x12B847C, 1),
    0xACE: (0x5EC, 0x5E4, 0x68C, 0x12C895C, 1),
    0xACF: (0x5ED, 0x5E5, 0x68D, 0x12C8984, 1),
    0xAAB: (0xEC, 0xE4, 0x18C, 0x12C83BC, 4),
    0xABB: (0x5E1, 0x5D9, 0x681, 0x12C8614, 1),
    0xA70: (0x4C, 0x44, 0xEC, 0x12C7A84, 4),
    0xAA8: (0x5DB, 0x5D3, 0x67B, 0x12C8344, 1),
    0xAAF: (0xF0, 0xE8, 0x190, 0x12C8434, 4),
    0xAB8: (0x108, 0x100, 0x1A8, 0x12C859C, 4),
    0xAC7: (0x138, 0x130, 0x1D8, 0x12C87F4, 4),
    0x9FA: (0x44, 0x3C, 0xE4, 0x12C67EC, 4),
}
for setting_id, (bank_offset, raw_offset, file_offset, instruction, size) in current_expected.items():
    entry = by_id[setting_id]
    assert int(entry['bank_offset'], 0) == bank_offset, entry
    assert int(entry['blob_offset'], 0) == raw_offset, entry
    assert int(entry['container_offset'], 0) == file_offset, entry
    assert int(entry['instruction_address'], 0) == instruction, entry
    assert entry['size'] == size, entry
assert serialized_offset(0xF7DC) == (0xF6D4, 'custom_0x1C00')
assert serialized_offset(0x113DC) == (None, 'outside_exported_segments')

value_labels = {
    0x858: {0: 'S / STILL IMAGE', 21: 'CH HIGH SPEED BURST', 23: 'CL LOW SPEED BURST'},
    0x827: {0: 'MS', 1: 'ES', 2: 'EF', 3: 'MS+ES', 4: 'EF+MS', 5: 'EF+MS+ES'},
    0xB: {0: 'CONTINUOUS', 2: '0.5 SEC', 3: '1.5 SEC', 5: 'OFF'},
}
enum_values = {}
for setting_id, labels in value_labels.items():
    pointer = b0.u64(0x1BD5AB8 + 8 * setting_id)
    rows = []
    for row_index in range(64):
        values = struct.unpack_from('<4I', b0.data, b0.off(pointer) + 16 * row_index)
        if values[0] == 0xFFFF:
            break
        stored = None if values[0] == 0x7FFFFFFE else values[0]
        raw = None if values[2] == 0x7FFFFFFE else values[2]
        rows.append({'row': row_index, 'stored': stored, 'raw': raw, 'label': labels.get(row_index),
                     'usb': None if values[3] == 0x7FFFFFFE else values[3]})
    enum_values[str(setting_id)] = {
        'table': f'0x{pointer:X}', 'stored_column': 0, 'raw_column': 2, 'usb_column': 3,
        'serialized_column': 'stored' if setting_id == 0xB else 'raw', 'rows': rows,
    }
assert next(row['raw'] for row in enum_values[str(0x858)]['rows'] if row['row'] == 21) is None
assert next(row['usb'] for row in enum_values[str(0x858)]['rows'] if row['row'] == 21) == 2
assert next(row['raw'] for row in enum_values[str(0x858)]['rows'] if row['row'] == 0) == 0
assert enum_values[str(0xB)]['rows'][0]['stored'] == 2
assert enum_values[str(0xB)]['rows'][5]['stored'] == 3
assert enum_values[str(0xB)]['rows'][0]['raw'] == 0x9D
assert enum_values[str(0xB)]['rows'][5]['raw'] == 0x87
assert enum_values[str(0xB)]['rows'][0]['usb'] == 0xFFFF

derived_value_labels = {
    str(0xACE): {0: 'S / STILL IMAGE', 21: 'CH HIGH SPEED BURST', 23: 'CL LOW SPEED BURST'},
    str(0xACF): {0: 'S / STILL IMAGE', 21: 'CH HIGH SPEED BURST', 23: 'CL LOW SPEED BURST'},
    str(0xAC7): {0: 'MS', 1: 'ES', 2: 'MS+ES', 3: 'EF', 4: 'EF+MS', 5: 'EF+MS+ES'},
    str(0xAAF): {125: 'ISO 125 (display output)'},
    str(0x8A0): {38: '1/25 s', 67: '1/8000 s', 70: '1/16000 s'},
    str(0xABB): {40: '1/25 s (display index)', 69: '1/8000 s (display index)', 72: '1/16000 s (display index)'},
}


def scenario_row(setting_id, scenario_name, raw_value, usb_value=None, note=None):
    return {**by_id[setting_id], 'scenario_name': scenario_name, 'scenario_raw_value': raw_value,
            'scenario_usb_value': usb_value, 'raw_value_note': note}


scenario = [
    scenario_row(0x858, 'DRIVE MODE / CH HIGH SPEED BURST', 1, 2,
                 'Current slot-7 field: 0→1. Use DOTLCD_CONTINUOUS*=21 to identify CH specifically; USB D201=2 is not a BACKUP byte.'),
    scenario_row(0x827, 'SHUTTER TYPE / current value in 02', 3, None,
                 'Real 01/02 blobs contain 3=EF, not the owner-reported ES=1. The 02B control has 2=MS+ES and 03_S has 1=ES.'),
    scenario_row(0x8A0, 'SHUTTER SPEED / 1/8000', 67, 125,
                 'M-mode current index. UI_SETP_SHUTTER_SPEED=0x89E and PC_EXPOSURETIME=0x991 use dynamic fallback; USB 0x500D is microseconds.'),
    scenario_row(0xB, 'IMAGE DISP / CONTINUOUS', 2, 0xFFFF,
                 'BACKUP stores table column 0: CONTINUOUS=2, OFF=3. Columns raw=0x9D/0x87 and USB=0xFFFF/0 are different representations.'),
    scenario_row(0xACE, 'DRIVE MODE / CH display row', 21),
    scenario_row(0xACF, 'DRIVE MODE / CH display row duplicate', 21),
    scenario_row(0xA70, 'DRIVE MODE / continuous derived flag', 1),
    scenario_row(0x874, 'DRIVE MODE / menu derived value', 1),
    scenario_row(0xAAB, 'SHUTTER SPEED / denominator times 100', 800000),
    scenario_row(0xABB, 'SHUTTER SPEED / display index', 69),
    scenario_row(0x8A9, 'SHUTTER SPEED / HIFREQ derived value', 600, None,
                 'The field name is UI_SETP_HIFREQ_FLKLESS_SHUTTER_SPEED_M; 1→600 is a shutter derivative, not BACKUP_SUMID.'),
    scenario_row(0xAB8, 'SHUTTER TYPE / DOTLCD output', 3, None,
                 'Actual output representation, not the menu enum: 02B changes 3→1 with MS+ES at 1/16000, consistent with actual ES; 03_S also has 1.'),
    scenario_row(0xAC7, 'SHUTTER TYPE / DOTLCD menu value', 3, None,
                 'DOTLCD mirror of the menu enum: 02→02B changes 3=EF→2=MS+ES. File 0x1D8/raw 0x130.'),
    scenario_row(0xAAF, 'EXPOSURE / DOTLCD ISO output', 0, None,
                 'Independent ISO display output, not shutter speed or MOVDC. 02B contains 125=ISO 125; its manual/auto cause is not established.'),
    scenario_row(0xAA8, 'FLASH / emit-test permission derivative', 1, None,
                 'Dependent flash output: 01/02/02B/03 values 0/1/0/1, so it is not an MS+ES or MOVDC marker; exact cause needs flash controls.'),
]

runtime_metadata = [
    {
        'name': 'SERVICE_SHUTCOUNT_CANDIDATE', 'ui_setp_candidate': '0x172 UI_SETP_SHUTCOUNT',
        'status': 'probable_monotonic_service_counter_not_statically_bound',
        'bank_offset': '0xF61C', 'blob_offset': '0xF614', 'container_offset': '0xF6BC',
        'segment': 'main_0xF6D4', 'size': 2, 'type': 'u16', 'checksum_covered': True,
        'reason': 'Real 01/02/02B/03 values 7429/8611/9158/9586 increase with shooting; exact UI_SETP binding remains a hypothesis.',
    },
    {
        'name': 'SERVICE_VOLATILE_U16_F67C', 'ui_setp_candidate': None,
        'status': 'unidentified_volatile_service_metadata',
        'bank_offset': '0xF684', 'blob_offset': '0xF67C', 'container_offset': '0xF724',
        'segment': 'main_0xF6D4', 'size': 2, 'type': 'u16', 'checksum_covered': False,
        'reason': 'Real 01/02/02B/03 values 64776/72/170/70 change with shooting and differ even at repeated 1/8000; outside the first checksum span ending at raw 0xF66D.',
    },
]

scenario_save_sites = []
for insn in fwcommon.insns(b0, 0x12DC790, (0x12E5AD4 - 0x12DC790) // 4):
    match = re.fullmatch(r'w0, #(0x[0-9a-f]+|\d+)', insn.op_str)
    if insn.mnemonic in ('mov', 'movz') and match and int(match.group(1), 0) in (0x858, 0x827, 0x89E, 0x991, 0x833, 0xB):
        scenario_save_sites.append({'address': f'0x{insn.address:X}', 'instruction': f'{insn.mnemonic} {insn.op_str}'})
assert not scenario_save_sites, scenario_save_sites

layout = {
    'firmware': catalog['firmware_id'], 'firmware_sha256': catalog['firmware_sha256'],
    'getter': f'0x{GETTER:X}', 'case_base': f'0x{CASE_BASE:X}', 'signed_offset_table': f'0x{OFFSET_TABLE:X}',
    'id_range': [1, ID_COUNT], 'settings_bank': f'0x{SETTINGS:X}', 'bank_size': f'0x{BANK_SIZE:X}',
    'destination_bank': '0x2578A18', 'returned_buffer': '0x2578A20', 'return_delta': 8,
    'container_magic': 'X-BACKUP0100', 'container_prefix': f'0x{CONTAINER_SIZE:X}',
    'formulas': {'raw_main_segment': 'raw = bank_offset - 8, for 8 <= bank_offset < 0xF6DC',
                 'raw_custom_segment': 'raw = bank_offset - 0x108, for 0xF7DC <= bank_offset < 0x113DC',
                 'with_container': 'file_offset = raw + 0xA8',
                 'outside': 'Other bank offsets are not present in the two-segment export and have null blob/container offsets.'},
    'export_segments': {'handler': '0x2BF2DD0', 'total_payload_bytes': 0x112D4,
                        'main': {'raw_range': [0, 0xF6D4], 'bank_range': [8, 0xF6DC], 'returned_by': '0x1133A04'},
                        'custom': {'raw_range': [0xF6D4, 0x112D4], 'bank_range': [0xF7DC, 0x113DC],
                                   'returned_by': '0x1133A18', 'ram_buffer': '0x25881F4', 'bytes': 0x1C00, 'slots': '7 x 0x400'},
                        'proof': '0x2BF2DF4 stores 0xF6D4 for segment 1; 0x2BF2E04 stores 0x1C00 for segment 2; 0x12DC5CC returns 0x25881F4.'},
    'current_map': {'custom_slot': 7, 'ui_bank_slot': 0, 'getter_mode': 0,
                    'status': 'Validated against real 01/02 BACKUP blobs; slot-7 selector-0 and selector-1 maps are identical for all 2431 direct IDs.',
                    'drive': 'raw 0x450/file 0x4F8 plus DOTLCD mirrors raw 0x5E4/0x5E5',
                    'shutter_speed_m': 'raw 0x50A/file 0x5B2 plus output raw 0xE4 and display index raw 0x5D9'},
    'mode_selector': {'function': '0x1133818', 'values': [0, 1],
                      'status': 'Only the legacy slot-0 alternatives depend on this selector; current slot-7 maps are identical.',
                      'mode0_scenario': 'Legacy Drive/Shutter Type use high bank offsets outside both exported segments.',
                      'mode1_scenario': 'Legacy custom copies use raw 0xF7E8/0xF875; they are not the current settings and must not be the decoder default.'},
    'checksum': {'validator': '0x12E5D9C', 'algorithm': 'zero u32 at raw+0x3C, then sum unsigned bytes modulo 2^32',
                 'raw_destination': 0x3C, 'bank_destination': 0x44,
                 'accepted_lengths': [0xF6D4, 0x112D4, 0x7AD4, 0x96D4],
                 'supported_spans': {hex(0xF6D4): [[0, 0x7A6D], [0x7AD4, 0x96D4]],
                                     hex(0x112D4): [[0, 0xF66D], [0xF6D4, 0x112D4]]},
                 'note': 'For 0x7AD4/0x96D4 the validator addresses a span up to 0x96D4; the surrounding buffer contract is unresolved, so the decoder does not claim to validate those variants.'},
    'container_builder': {'function': '0x2CCE0C0', 'magic_file_offset': 8,
                          'proof': 'memcpy 8 bytes X-BACKUP to header+8, then 4 bytes 0100 to header+0x10; main data starts at header+0xA8.'},
    'transformations': {'function': '0x12E5AD4',
                        'children': ['0x12DC790', '0x12DFF18', '0x12E04B0', '0x12E1904', '0x12E1A88', '0x12E1B54',
                                     '0x12E1C1C', '0x12E1DE0', '0x12E1F9C', '0x12E4AA4', '0x12E542C'],
                        'effect': 'In-place property-dependent writes/conversions in the destination bank; not a simple byte-for-byte copy of live settings.',
                        'scenario_scan': 'No literal UI_SETP 0x858, 0x827, 0x89E, 0x991, 0x833 or 0xB occurs in the save-transform range 0x12DC790..0x12E5AD4.',
                        'layout_note': 'No separate reordering or compression pass is established in this chain; full value semantics and all variants remain unresolved.'},
    'assumptions': ['Default current map uses custom slot 7 (w19=7), UI bank slot 0 (w22=0), getter mode w20=0.',
                    'Selector w23 does not change any direct current-slot field: both selector maps have 2431 identical IDs.',
                    'Legacy mode0/mode1 remain available for inspecting alternate custom-bank copies, not for decoding current settings by default.'],
    'unresolved': ['Full semantics of every backup transformation in 0x12E5AD4 are not established; values are raw serialized values, not guaranteed live-UI values.',
                   'SERVICE_SHUTCOUNT_CANDIDATE is dynamically probable but not statically bound to UI_SETP 0x172; SERVICE_VOLATILE_U16_F67C has no established name or units.',
                   'No decompressor is inferred: no compression stage is established in the identified copy path, but its absence is not proven for every variant.'],
}
result = {
    'layout': layout,
    'statistics': {'ids_total': ID_COUNT, 'ids_with_direct_bank_field_current': len(entries),
                   'ids_with_direct_bank_field_mode0': len(entries_by_mode[0]),
                   'ids_with_direct_bank_field_mode1': len(entries_mode1), 'ids_without_direct_bank_field': len(without_field),
                   'serialized_fields_current': sum(entry['blob_offset'] is not None for entry in entries),
                   'serialized_fields_mode0': sum(entry['blob_offset'] is not None for entry in entries_by_mode[0]),
                   'serialized_fields_mode1': sum(entry['blob_offset'] is not None for entry in entries_mode1)},
    'scenario_layout_mode': 'current',
    'scenario': scenario,
    'legacy_scenario_candidates': {
        'mode1_drive': {'bank_offset': '0xF8F0', 'blob_offset': '0xF7E8', 'container_offset': '0xF890'},
        'mode1_shutter_type': {'bank_offset': '0xF97D', 'blob_offset': '0xF875', 'container_offset': '0xF91D'},
        'reason': 'These are alternate custom-bank copies selected by the old slot-0 assumption; real Drive remains unchanged there.',
    },
    'enum_values': enum_values,
    'derived_value_labels': derived_value_labels,
    'runtime_metadata': runtime_metadata,
    'entries': entries,
    'entries_current': entries,
    'entries_current_mode0': current_by_mode[0],
    'entries_current_mode1': current_by_mode[1],
    'entries_mode0': entries_by_mode[0],
    'entries_mode1': entries_mode1,
    'without_direct_bank_field': without_field,
}
(HERE / 'карта_банка.json').write_text(json.dumps(result, ensure_ascii=False, indent=2) + '\n', encoding='utf-8')
with (HERE / 'карта_банка.tsv').open('w', encoding='utf-8', newline='') as stream:
    columns = ['layout_mode', 'custom_slot', 'selector_mode', 'ui_setp', 'id', 'name', 'bkup_names', 'case',
               'bank_offset', 'blob_offset', 'container_offset', 'segment', 'size', 'type', 'instruction_address', 'instruction']
    writer = csv.DictWriter(stream, fieldnames=columns, delimiter='\t', extrasaction='ignore')
    writer.writeheader()
    for rowset in (entries, entries_by_mode[0], entries_mode1):
        for entry in rowset:
            writer.writerow({**entry, 'bkup_names': '|'.join(entry['bkup_names'])})
print(f"OK: current={len(entries)}, legacy mode0={len(entries_by_mode[0])}, mode1={len(entries_mode1)}, "
      f"without field={len(without_field)}; current slot-7 scenario offsets verified")
