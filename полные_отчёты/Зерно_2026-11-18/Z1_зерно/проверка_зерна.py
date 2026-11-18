import hashlib
import json
import sys
from pathlib import Path

ROOT = Path(r'<корень проекта>\Анализ_прошивки')
TASK = ROOT / 'Зерно_2026-11-18' / 'Z1_зерно'
K2 = ROOT / 'Камера_2026-11-17' / 'K2_прошивка'
sys.path.insert(0, str(K2))
import decode_backup

MAP_PATH = K2 / 'карта_банка.json'
BACKUP_PATH = ROOT / 'fujicli_2026-11-18' / 'совместимость' / 'снимки' / '04_после_set_c7' / 'backup.bin'
EXPECTED_CODES = [6, 6, 3, 7, 6, 6, 6]


def d195_code(grain: int, size: int) -> int:
    """Decode bank bytes: GRAIN 0=Strong, 1=Weak, 2=Off; SIZE 0=Small, 1=Large."""
    if size not in (0, 1):
        raise ValueError(f'Unexpected GRAIN_SIZE={size}')
    if grain == 2:
        return 6 + size
    if grain in (0, 1):
        return 3 + 2 * size - grain
    raise ValueError(f'Unexpected GRAIN={grain}')


m = decode_backup.load_map(MAP_PATH)
blob = BACKUP_PATH.read_bytes()
payload, container, warnings = decode_backup.split_container(blob)
mode1 = {row['name']: row for row in m['entries_mode1']
         if row['name'] in ('UI_SETP_GRAIN', 'UI_SETP_GRAIN_SIZE')}
if set(mode1) != {'UI_SETP_GRAIN', 'UI_SETP_GRAIN_SIZE'}:
    raise RuntimeError('GRAIN rows absent from mode1 bank map')
if any(row['segment'] != 'custom_0x1C00' for row in mode1.values()):
    raise RuntimeError('GRAIN rows do not point to custom segment')
base_grain = int(mode1['UI_SETP_GRAIN']['blob_offset'], 0)
base_size = int(mode1['UI_SETP_GRAIN_SIZE']['blob_offset'], 0)
if base_size != base_grain + 1:
    raise RuntimeError('GRAIN and GRAIN_SIZE are not adjacent in map')

slots = []
for slot in range(7):
    grain_offset = base_grain + slot * 0x400
    size_offset = base_size + slot * 0x400
    grain = payload[grain_offset]
    size = payload[size_offset]
    code = d195_code(grain, size)
    slots.append({
        'slot': f'C{slot + 1}',
        'slot_index_zero_based': slot,
        'bank_field_offset': hex(int(mode1['UI_SETP_GRAIN']['bank_offset'], 0) + slot * 0x400),
        'payload_offsets': {'GRAIN': hex(grain_offset), 'GRAIN_SIZE': hex(size_offset)},
        'values': {'GRAIN': grain, 'GRAIN_SIZE': size},
        'decoded_D195': code,
        'matches_observation': code == EXPECTED_CODES[slot],
    })

write_rules = [
    {'D195': 1, 'label': 'Off', 'GRAIN': 2, 'GRAIN_SIZE': 'preserve',
     'evidence': 'model; consistent with the observed accepted write 1, unchanged read 6, and unchanged backup bytes'},
    {'D195': 2, 'label': 'Weak/Small', 'GRAIN': 1, 'GRAIN_SIZE': 0,
     'evidence': 'inferred inverse mapping; not tested on camera'},
    {'D195': 3, 'label': 'Strong/Small', 'GRAIN': 0, 'GRAIN_SIZE': 0,
     'evidence': 'inferred inverse mapping; not tested on camera'},
    {'D195': 4, 'label': 'Weak/Large', 'GRAIN': 1, 'GRAIN_SIZE': 1,
     'evidence': 'inferred inverse mapping; not tested on camera'},
    {'D195': 5, 'label': 'Strong/Large', 'GRAIN': 0, 'GRAIN_SIZE': 1,
     'evidence': 'inferred inverse mapping; not tested on camera'},
]
result = {
    'task': 'Z1 — USB-свойство зерна слота D195',
    'firmware': 'X-H2 5.30',
    'source_backup': str(BACKUP_PATH),
    'backup_sha256': hashlib.sha256(blob).hexdigest(),
    'backup_bytes': len(blob),
    'payload_bytes': len(payload),
    'payload_offset_in_file': hex(container['payload_offset']),
    'layout_mode': 'mode1; legacy custom-slot projection used only to read seven custom blocks',
    'custom_segment': {'payload_start': '0xF6D4', 'bytes': '0x1C00', 'slot_stride': '0x400'},
    'map_fields': {
        'UI_SETP_GRAIN': {'id': '0x106', 'getter': '0x12B71C4', 'first_payload_offset': hex(base_grain)},
        'UI_SETP_GRAIN_SIZE': {'id': '0x107', 'getter': '0x12B727C', 'first_payload_offset': hex(base_size)},
    },
    'read_formula': {
        'bank_encoding': {'GRAIN_0': 'Strong', 'GRAIN_1': 'Weak', 'GRAIN_2': 'Off',
                          'GRAIN_SIZE_0': 'Small', 'GRAIN_SIZE_1': 'Large'},
        'expression': 'if GRAIN == 2: D195 = 6 + GRAIN_SIZE; else: D195 = 3 + 2*GRAIN_SIZE - GRAIN',
    },
    'write_rules': write_rules,
    'write_range_evidence': {
        'observed_accepted': [1],
        'observed_rejected': [6],
        'not_tested': [2, 3, 4, 5, 7],
        'rejection_response': '0x201C Invalid_DeviceProp_Value',
        'note': 'The 1..5 input range is inferred from the read mapping; only 1 accepted and 6 rejected were observed. GetDevicePropDesc (0x1014) for D195 returned 0x2002 in the recorded RAW CONV session; the static instruction that emits 0x201C was not isolated.',
    },
    'slot_check': {'expected': EXPECTED_CODES, 'actual': [row['decoded_D195'] for row in slots],
                   'all_match': [row['decoded_D195'] for row in slots] == EXPECTED_CODES, 'slots': slots},
    'code_addresses': {
        'property_group_table_start': '0x3443590',
        'property_group_table_end_inclusive': '0x34435DC',
        'D195_entry': '0x34435AC',
        'property_group_metadata_builder': '0x2F2CDE0',
        'group_member_helper': '0x2F2C838',
        'bank_getter_dispatcher': '0x12AA788',
        'slot_selector_helper': '0x11DA370',
        'grain_case': '0x12B71C4',
        'grain_size_case': '0x12B727C',
    },
    'unicorn': {'run': False, 'reason': 'The bank-byte addresses and slot stride were checked against the 5.30 map and disassembly; a full emulation would require reconstructing the surrounding bank/context globals.'},
    'camera_touched': False,
}
if not result['slot_check']['all_match']:
    raise SystemExit('Slot formula does not match observed D195 sequence')
(TASK / 'результат.json').write_text(json.dumps(result, ensure_ascii=False, indent=2) + '\n', encoding='utf-8')
print(json.dumps(result['slot_check'], ensure_ascii=False, indent=2))
print('sha256', result['backup_sha256'])
