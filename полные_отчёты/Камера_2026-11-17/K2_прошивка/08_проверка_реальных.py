import csv
import hashlib
import json
import subprocess
import sys
from pathlib import Path

HERE = Path(__file__).resolve().parent
SNAPSHOTS = HERE.parent / 'K1_камера' / 'снимки_серия'
INPUTS = {
    '01_база': ('01_база', 'e52c4dd8f4cec79703717f0f7031c23220714f1ca5fff6dd0e6a3e7e4017c946'),
    '02_CH_ES_8000_CONT': ('02_CH_ES_8000_CONT', '2c44dd69f85cbadde690d95c9524384520fa43f5cc7864cb222f47e5ef798604'),
    '02B_CH_MSES_16000_CONT_успех': ('02B_CH_MSES_16000_CONT_успех', 'cd0b365c5a23f0f1ad3a4696aa6c47462d2f4d542f1d565a95715d45b3f95b5a'),
    '03_S': ('03_S', 'abfe26aff4e0d86fbdfc149df521a123a2ab4314627770ebe0beb772a4aa3ac7'),
}
EXPECTED = {
    'UI_SETP_HIFREQ_FLKLESS_SHUTTER_SPEED_M': (0x18, 1, 600, 'shutter_derivative'),
    'UI_SETP_STILL_MENU_POS_TAB': (0x24, 294, 293, 'menu_navigation'),
    'UI_SETP_STILL_MENU_POS_ITEM': (0x28, 570, 163, 'menu_navigation'),
    'UI_SETP_SETUP_MENU_POS_ITEM_1': (0x34, 162, 163, 'menu_navigation'),
    'UI_SETP_SETUP_MENU_POS_ITEM_2': (0x38, 167, 335, 'menu_navigation'),
    'UI_SETP_SETTING_CHKSUM': (0x3C, 73963, 74192, 'checksum'),
    'UI_SETP_DOTLCD_CONTMODE': (0x44, 0, 1, 'drive_derivative'),
    'UI_SETP_DOTLCD_SHUTERSPEED_OUTPUT': (0xE4, 2500, 800000, 'shutter_derivative'),
    'UI_SETP_REC_VIEW': (0x1F3, 3, 2, 'scenario_setting'),
    'UI_SETP_DRV_MENU': (0x425, 0, 1, 'drive_derivative'),
    'UI_SETP_CONTINUOUS': (0x450, 0, 1, 'drive_current'),
    'UI_SETP_SHUTTER_SPEED_M': (0x50A, 38, 67, 'shutter_current'),
    'UI_SETP_DOTLCD_EXTFLASHEMITTESTPERMIT': (0x5D3, 0, 1, 'dependent_output'),
    'UI_SETP_DOTLCD_SHUTTERSPEED': (0x5D9, 40, 69, 'shutter_derivative'),
    'UI_SETP_DOTLCD_CONTINUOUS': (0x5E4, 0, 21, 'drive_display_row'),
    'UI_SETP_DOTLCD_CONTINUOUS2': (0x5E5, 0, 21, 'drive_display_row_duplicate'),
    'UI_SETP_SETUP_COMM_MENU_POS_ITEM': (0xEB4, 570, 569, 'menu_navigation'),
}
EXPECTED_SERVICE = {
    'SERVICE_SHUTCOUNT_CANDIDATE': (0xF614, 7429, 8611, 'probable_shutter_count'),
    'SERVICE_VOLATILE_U16_F67C': (0xF67C, 64776, 72, 'unidentified_volatile_metadata'),
}


def run(*arguments):
    completed = subprocess.run(
        [sys.executable, '-B', str(HERE / 'decode_backup.py'), *map(str, arguments)],
        check=True, capture_output=True, text=True, encoding='utf-8')
    return json.loads(completed.stdout)


def read_input(key):
    directory, expected_hash = INPUTS[key]
    path = SNAPSHOTS / directory / 'backup.bin'
    data = path.read_bytes()
    assert len(data) == 70524
    assert hashlib.sha256(data).hexdigest() == expected_hash
    assert data[8:20] == b'X-BACKUP0100'
    return path, data


paths, original = {}, {}
for key in INPUTS:
    paths[key], original[key] = read_input(key)

base = run(paths['01_база'])
scenario = run(paths['02_CH_ES_8000_CONT'])
compared = run('--diff', paths['01_база'], paths['02_CH_ES_8000_CONT'])
for decoded in (base, scenario):
    assert decoded['layout_mode'] == 'current'
    assert decoded['container']['payload_offset'] == 0xA8
    assert decoded['payload_length'] == 70356 == 0x112D4
    assert decoded['checksum']['valid'] is True
    assert decoded['record_0x4c_candidates'] == []
assert compared['layout_mode'] == 'current'
assert compared['changed_count'] == 17
assert compared['changed_service_count'] == 2
assert compared['changed_byte_count'] == 27
assert compared['explained_changed_byte_count'] == 27
assert compared['unexplained_changed_byte_count'] == 0
assert compared['unknown_changed_ranges'] == []
assert compared['record_0x4c_candidates'] == {'old': [], 'new': []}
assert set(compared['changed']) == set(EXPECTED)
assert set(compared['changed_service_fields']) == set(EXPECTED_SERVICE)

old_payload = original['01_база'][0xA8:]
new_payload = original['02_CH_ES_8000_CONT'][0xA8:]
rows = []
for name, (raw_offset, old_value, new_value, category) in EXPECTED.items():
    pair = compared['changed'][name]
    before, after = pair['old'], pair['new']
    assert before['raw_offset'] == raw_offset
    assert before['file_offset'] == raw_offset + 0xA8
    assert before['value'] == old_value and after['value'] == new_value
    changed_bytes = []
    for offset in range(raw_offset, raw_offset + before['size']):
        if old_payload[offset] != new_payload[offset]:
            changed_bytes.append({'raw_offset': offset, 'file_offset': offset + 0xA8,
                                  'old': f'0x{old_payload[offset]:02X}', 'new': f'0x{new_payload[offset]:02X}'})
    assert changed_bytes
    rows.append({'name': name, 'kind': 'UI_SETP', 'id': before['id'], 'category': category,
                 'raw_offset': raw_offset, 'file_offset': raw_offset + 0xA8, 'size': before['size'],
                 'old': old_value, 'new': new_value, 'new_labels': after['value_labels'],
                 'instruction_address': before['instruction_address'], 'changed_bytes': changed_bytes})
for name, (raw_offset, old_value, new_value, category) in EXPECTED_SERVICE.items():
    pair = compared['changed_service_fields'][name]
    before, after = pair['old'], pair['new']
    assert before['raw_offset'] == raw_offset
    assert before['file_offset'] == raw_offset + 0xA8
    assert before['value'] == old_value and after['value'] == new_value
    changed_bytes = []
    for offset in range(raw_offset, raw_offset + before['size']):
        if old_payload[offset] != new_payload[offset]:
            changed_bytes.append({'raw_offset': offset, 'file_offset': offset + 0xA8,
                                  'old': f'0x{old_payload[offset]:02X}', 'new': f'0x{new_payload[offset]:02X}'})
    assert changed_bytes
    rows.append({'name': name, 'kind': 'service_metadata', 'id': before.get('ui_setp_candidate'),
                 'category': category, 'status': before['status'], 'reason': before['reason'],
                 'raw_offset': raw_offset, 'file_offset': raw_offset + 0xA8, 'size': before['size'],
                 'old': old_value, 'new': new_value, 'changed_bytes': changed_bytes})

actual_changed_files = {index for index, (before, after) in enumerate(zip(original['01_база'], original['02_CH_ES_8000_CONT']))
                        if before != after}
explained_files = {change['file_offset'] for row in rows for change in row['changed_bytes']}
assert actual_changed_files == explained_files
assert len(actual_changed_files) == 27
assert sum(len(row['changed_bytes']) for row in rows) == 27

checksum_before = compared['old']['checksum']['stored_u32']
checksum_after = compared['new']['checksum']['stored_u32']
spans = compared['new']['checksum']['spans']
signed_delta = sum(new_payload[offset] - old_payload[offset]
                   for start, end in spans for offset in range(start, end)
                   if not 0x3C <= offset < 0x40)
assert checksum_before == 73963 and checksum_after == 74192
assert signed_delta == checksum_after - checksum_before == 229
assert all(not start <= 0xF67C < end for start, end in spans)

assert all(row.get('matches_expected') is True for row in scenario['scenario_fields'])
assert base['settings']['UI_SETP_SHUTTER_TYPE']['value_labels'] == ['EF']
assert scenario['settings']['UI_SETP_SHUTTER_TYPE']['value_labels'] == ['EF']

controls = {}
for key in ('02B_CH_MSES_16000_CONT_успех', '03_S'):
    decoded = run(paths[key])
    assert decoded['checksum']['valid'] is True
    assert decoded['record_0x4c_candidates'] == []
    controls[key] = {
        'sha256': INPUTS[key][1],
        'shutter_type': decoded['settings']['UI_SETP_SHUTTER_TYPE']['value'],
        'shutter_type_labels': decoded['settings']['UI_SETP_SHUTTER_TYPE']['value_labels'],
        'shutter_speed_m': decoded['settings']['UI_SETP_SHUTTER_SPEED_M']['value'],
        'shutter_denominator_x100': decoded['settings']['UI_SETP_DOTLCD_SHUTERSPEED_OUTPUT']['value'],
        'drive_display_row': decoded['settings']['UI_SETP_DOTLCD_CONTINUOUS']['value'],
        'image_disp': decoded['settings']['UI_SETP_REC_VIEW']['value'],
        'service_f614': decoded['service_fields']['SERVICE_SHUTCOUNT_CANDIDATE']['value'],
        'service_f67c': decoded['service_fields']['SERVICE_VOLATILE_U16_F67C']['value'],
    }
assert controls['02B_CH_MSES_16000_CONT_успех']['shutter_type_labels'] == ['MS+ES']
assert controls['03_S']['shutter_type_labels'] == ['ES']
series = [7429, 8611, controls['02B_CH_MSES_16000_CONT_успех']['service_f614'], controls['03_S']['service_f614']]
assert series == sorted(series) and len(set(series)) == len(series)
assert controls['03_S']['shutter_denominator_x100'] == 800000
assert scenario['settings']['UI_SETP_DOTLCD_SHUTERSPEED_OUTPUT']['value'] == controls['03_S']['shutter_denominator_x100']
assert scenario['service_fields']['SERVICE_VOLATILE_U16_F67C']['value'] != controls['03_S']['service_f67c']

for key, path in paths.items():
    assert hashlib.sha256(path.read_bytes()).hexdigest() == INPUTS[key][1]

result = {
    'all_checks_passed': True, 'real_camera_blob_used': True, 'camera_accessed_by_this_script': False,
    'layout_mode': 'current', 'custom_slot': 7,
    'required_inputs': {key: {'path': str(paths[key]), 'sha256': INPUTS[key][1], 'bytes': 70524,
                              'payload_bytes': 70356, 'checksum_valid': True}
                        for key in ('01_база', '02_CH_ES_8000_CONT')},
    'totals': {'changed_bytes': 27, 'explained_changed_bytes': 27, 'unexplained_changed_bytes': 0,
               'changed_ui_fields': 17, 'changed_service_fields': 2,
               'ui_bytes': sum(len(row['changed_bytes']) for row in rows if row['kind'] == 'UI_SETP'),
               'service_bytes': sum(len(row['changed_bytes']) for row in rows if row['kind'] == 'service_metadata')},
    'changed_fields': rows,
    'checksum_proof': {'old': checksum_before, 'new': checksum_after, 'delta': 229,
                       'sum_of_other_byte_deltas': signed_delta, 'f67c_covered': False},
    'controls': controls,
    'owner_label_mismatch': 'Current UI_SETP_SHUTTER_TYPE is 3=EF in both required blobs, not ES=1. 02B has 2=MS+ES; 03_S has 1=ES.',
    'record_0x4c': {
        'full_signature_in_required_blobs': False, 'unexplained_changed_bytes': 0,
        'conclusion': 'No full record 0x4C and no unexplained guard-flag candidate are observed in these BACKUP blobs. A theoretical service projection of a scalar into the UI bank is not categorically excluded, but there is no evidence for MOVDC guard persistence here.',
    },
    'cli_verified': ['python decode_backup.py <backup.bin>', 'python decode_backup.py --diff <01/backup.bin> <02/backup.bin>'],
}
(HERE / 'реальные_блобы.json').write_text(json.dumps(result, ensure_ascii=False, indent=2) + '\n', encoding='utf-8')
with (HERE / 'реальный_diff.tsv').open('w', encoding='utf-8', newline='') as stream:
    columns = ['name', 'kind', 'id', 'category', 'raw_offset', 'file_offset', 'size', 'old', 'new', 'changed_bytes', 'status_or_labels']
    writer = csv.DictWriter(stream, fieldnames=columns, delimiter='\t', extrasaction='ignore')
    writer.writeheader()
    for row in rows:
        writer.writerow({**row, 'raw_offset': f"0x{row['raw_offset']:X}", 'file_offset': f"0x{row['file_offset']:X}",
                         'changed_bytes': '|'.join(f"0x{change['file_offset']:X}:{change['old']}>{change['new']}" for change in row['changed_bytes']),
                         'status_or_labels': row.get('status') or ','.join(row.get('new_labels', []))})
print('OK: real CLI decode/diff; 27/27 bytes explained (17 UI fields + 2 service fields), checksum delta 229, no record 0x4C signature')
