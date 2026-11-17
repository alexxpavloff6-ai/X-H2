import csv
import hashlib
import json
import subprocess
import sys
from pathlib import Path

HERE = Path(__file__).resolve().parent
SNAPSHOTS = HERE.parent / 'K1_камера' / 'снимки_серия'
INPUTS = {
    '02': ('02_CH_ES_8000_CONT', '2c44dd69f85cbadde690d95c9524384520fa43f5cc7864cb222f47e5ef798604'),
    '02B': ('02B_CH_MSES_16000_CONT_успех', 'cd0b365c5a23f0f1ad3a4696aa6c47462d2f4d542f1d565a95715d45b3f95b5a'),
    '01': ('01_база', 'e52c4dd8f4cec79703717f0f7031c23220714f1ca5fff6dd0e6a3e7e4017c946'),
    '03': ('03_S', 'abfe26aff4e0d86fbdfc149df521a123a2ab4314627770ebe0beb772a4aa3ac7'),
}
EXPECTED = {
    'UI_SETP_STILL_MENU_POS_TAB': (0x24, 293, 282, 'menu_navigation'),
    'UI_SETP_STILL_MENU_POS_ITEM': (0x28, 163, 221, 'menu_navigation'),
    'UI_SETP_SETUP_MENU_POS_ITEM_1': (0x34, 163, 240, 'menu_navigation'),
    'UI_SETP_SETUP_MENU_POS_ITEM_2': (0x38, 335, 185, 'menu_navigation'),
    'UI_SETP_SETTING_CHKSUM': (0x3C, 74192, 74649, 'checksum'),
    'UI_SETP_DOTLCD_SHUTERSPEED_OUTPUT': (0xE4, 800000, 1600000, 'shutter_derivative'),
    'UI_SETP_DOTLCD_ISO_OUTPUT': (0xE8, 0, 125, 'iso_display_output'),
    'UI_SETP_DOTLCD_SHUTTERTYPE_OUTPUT': (0x100, 3, 1, 'actual_shutter_output'),
    'UI_SETP_DOTLCD_SHUTTERTYPE': (0x130, 3, 2, 'shutter_type_dotlcd'),
    'UI_SETP_SHUTTER_SPEED_M': (0x50A, 67, 70, 'shutter_current'),
    'UI_SETP_SHUTTER_TYPE': (0x592, 3, 2, 'shutter_type_current'),
    'UI_SETP_DOTLCD_EXTFLASHEMITTESTPERMIT': (0x5D3, 1, 0, 'flash_emit_test_permit'),
    'UI_SETP_DOTLCD_SHUTTERSPEED': (0x5D9, 69, 72, 'shutter_derivative'),
}
EXPECTED_SERVICE = {
    'SERVICE_SHUTCOUNT_CANDIDATE': (0xF614, 8611, 9158, 'probable_shutter_count'),
    'SERVICE_VOLATILE_U16_F67C': (0xF67C, 72, 170, 'unidentified_volatile_metadata'),
}


def run(*arguments):
    completed = subprocess.run(
        [sys.executable, '-B', str(HERE / 'decode_backup.py'), *map(str, arguments)],
        check=True, capture_output=True, text=True, encoding='utf-8')
    return json.loads(completed.stdout)


paths, original = {}, {}
for key, (directory, expected_hash) in INPUTS.items():
    path = SNAPSHOTS / directory / 'backup.bin'
    data = path.read_bytes()
    assert len(data) == 70524
    assert hashlib.sha256(data).hexdigest() == expected_hash
    assert data[8:20] == b'X-BACKUP0100'
    paths[key], original[key] = path, data

before = run(paths['02'])
after = run(paths['02B'])
compared = run('--diff', paths['02'], paths['02B'])
legacy_before = run('--layout', 'mode1', paths['02'])
legacy_after = run('--layout', 'mode1', paths['02B'])
for decoded in (before, after):
    assert decoded['layout_mode'] == 'current'
    assert decoded['container']['payload_offset'] == 0xA8
    assert decoded['payload_length'] == 70356
    assert decoded['checksum']['valid'] is True
    assert decoded['record_0x4c_candidates'] == []
assert compared['changed_count'] == 13
assert compared['changed_service_count'] == 2
assert compared['changed_byte_count'] == 19
assert compared['explained_changed_byte_count'] == 19
assert compared['unexplained_changed_byte_count'] == 0
assert compared['unknown_changed_ranges'] == []
assert compared['record_0x4c_candidates'] == {'old': [], 'new': []}
assert set(compared['changed']) == set(EXPECTED)
assert set(compared['changed_service_fields']) == set(EXPECTED_SERVICE)
assert after['settings']['UI_SETP_SHUTTER_TYPE']['value_labels'] == ['MS+ES']
assert after['settings']['UI_SETP_DOTLCD_SHUTTERTYPE']['value_labels'] == ['MS+ES']
assert after['settings']['UI_SETP_DOTLCD_SHUTTERTYPE_OUTPUT']['value'] == 1
assert after['settings']['UI_SETP_DOTLCD_ISO_OUTPUT']['value_labels'] == ['ISO 125 (display output)']
assert after['settings']['UI_SETP_SHUTTER_SPEED_M']['value_labels'] == ['1/16000 s']
assert after['settings']['UI_SETP_DOTLCD_SHUTTERSPEED']['value_labels'] == ['1/16000 s (display index)']
for legacy in (legacy_before, legacy_after):
    item = legacy['settings']['UI_SETP_SHUTTER_TYPE']
    assert item['raw_offset'] == 0xF875 and item['file_offset'] == 0xF91D and item['value'] == 1

old_payload = original['02'][0xA8:]
new_payload = original['02B'][0xA8:]
rows = []
for name, (raw_offset, old_value, new_value, category) in EXPECTED.items():
    pair = compared['changed'][name]
    old_item, new_item = pair['old'], pair['new']
    assert old_item['raw_offset'] == raw_offset and old_item['file_offset'] == raw_offset + 0xA8
    assert old_item['value'] == old_value and new_item['value'] == new_value
    changed_bytes = [{'raw_offset': offset, 'file_offset': offset + 0xA8,
                      'old': f'0x{old_payload[offset]:02X}', 'new': f'0x{new_payload[offset]:02X}'}
                     for offset in range(raw_offset, raw_offset + old_item['size'])
                     if old_payload[offset] != new_payload[offset]]
    assert changed_bytes
    rows.append({'name': name, 'kind': 'UI_SETP', 'id': old_item['id'], 'category': category,
                 'raw_offset': raw_offset, 'file_offset': raw_offset + 0xA8, 'size': old_item['size'],
                 'old': old_value, 'new': new_value, 'new_labels': new_item['value_labels'],
                 'instruction_address': old_item['instruction_address'], 'changed_bytes': changed_bytes})
for name, (raw_offset, old_value, new_value, category) in EXPECTED_SERVICE.items():
    pair = compared['changed_service_fields'][name]
    old_item, new_item = pair['old'], pair['new']
    assert old_item['raw_offset'] == raw_offset and old_item['file_offset'] == raw_offset + 0xA8
    assert old_item['value'] == old_value and new_item['value'] == new_value
    changed_bytes = [{'raw_offset': offset, 'file_offset': offset + 0xA8,
                      'old': f'0x{old_payload[offset]:02X}', 'new': f'0x{new_payload[offset]:02X}'}
                     for offset in range(raw_offset, raw_offset + old_item['size'])
                     if old_payload[offset] != new_payload[offset]]
    assert changed_bytes
    rows.append({'name': name, 'kind': 'service_metadata', 'id': old_item.get('ui_setp_candidate'),
                 'category': category, 'status': old_item['status'], 'reason': old_item['reason'],
                 'raw_offset': raw_offset, 'file_offset': raw_offset + 0xA8, 'size': old_item['size'],
                 'old': old_value, 'new': new_value, 'changed_bytes': changed_bytes})

actual_changed_files = {index for index, (old, new) in enumerate(zip(original['02'], original['02B'])) if old != new}
explained_files = {change['file_offset'] for row in rows for change in row['changed_bytes']}
assert actual_changed_files == explained_files and len(actual_changed_files) == 19
spans = compared['new']['checksum']['spans']
signed_delta = sum(new_payload[offset] - old_payload[offset]
                   for start, end in spans for offset in range(start, end)
                   if not 0x3C <= offset < 0x40)
checksum_before = compared['old']['checksum']['stored_u32']
checksum_after = compared['new']['checksum']['stored_u32']
assert signed_delta == checksum_after - checksum_before == 457

series = {}
for key in ('01', '02', '02B', '03'):
    decoded = before if key == '02' else after if key == '02B' else run(paths[key])
    assert decoded['record_0x4c_candidates'] == []
    series[key] = {
        'shutter_type': decoded['settings']['UI_SETP_SHUTTER_TYPE']['value'],
        'shutter_type_labels': decoded['settings']['UI_SETP_SHUTTER_TYPE']['value_labels'],
        'dotlcd_shutter_type': decoded['settings']['UI_SETP_DOTLCD_SHUTTERTYPE']['value'],
        'actual_shutter_output': decoded['settings']['UI_SETP_DOTLCD_SHUTTERTYPE_OUTPUT']['value'],
        'iso_output': decoded['settings']['UI_SETP_DOTLCD_ISO_OUTPUT']['value'],
        'flash_emit_test_permit': decoded['settings']['UI_SETP_DOTLCD_EXTFLASHEMITTESTPERMIT']['value'],
        'shutter_speed_m': decoded['settings']['UI_SETP_SHUTTER_SPEED_M']['value'],
        'shutter_denominator_x100': decoded['settings']['UI_SETP_DOTLCD_SHUTERSPEED_OUTPUT']['value'],
        'service_f614': decoded['service_fields']['SERVICE_SHUTCOUNT_CANDIDATE']['value'],
        'service_f67c': decoded['service_fields']['SERVICE_VOLATILE_U16_F67C']['value'],
    }
assert [row['iso_output'] for row in series.values()] == [0, 0, 125, 0]
assert [row['flash_emit_test_permit'] for row in series.values()] == [0, 1, 0, 1]
assert [row['shutter_type'] for row in series.values()] == [3, 3, 2, 1]
assert [row['service_f614'] for row in series.values()] == [7429, 8611, 9158, 9586]
for key, path in paths.items():
    assert hashlib.sha256(path.read_bytes()).hexdigest() == INPUTS[key][1]

result = {
    'all_checks_passed': True, 'real_camera_blob_used': True, 'camera_accessed_by_this_script': False,
    'diff': '02_CH_ES_8000_CONT → 02B_CH_MSES_16000_CONT_успех', 'layout_mode': 'current',
    'totals': {'changed_bytes': 19, 'explained_changed_bytes': 19, 'unexplained_changed_bytes': 0,
               'changed_ui_fields': 13, 'changed_service_fields': 2,
               'ui_bytes': sum(len(row['changed_bytes']) for row in rows if row['kind'] == 'UI_SETP'),
               'service_bytes': sum(len(row['changed_bytes']) for row in rows if row['kind'] == 'service_metadata')},
    'changed_fields': rows,
    'shutter_type_calibration': {
        'current_menu': {'id': '0x827', 'file': '0x63A', 'raw': '0x592', 'change': '3=EF → 2=MS+ES'},
        'dotlcd_menu': {'id': '0xAC7', 'file': '0x1D8', 'raw': '0x130', 'change': '3=EF → 2=MS+ES'},
        'actual_output': {'id': '0xAB8', 'file': '0x1A8', 'raw': '0x100', 'change': '3→1',
                          'meaning': '1 occurs for MS+ES at 1/16000 and ES at 1/8000; consistent with actual electronic shutter'},
        'legacy_custom_copy': {'file': '0xF91D', 'raw': '0xF875', 'value_in_both': 1,
                               'warning': 'This is not the current shutter type and must not be used for calibration.'},
    },
    'field_explanations': {
        '0x190': 'UI_SETP_DOTLCD_ISO_OUTPUT u32: 0→125, i.e. ISO 125 display output; not exposure time or MOVDC. Manual/auto cause is not established by these blobs.',
        '0x67B': 'UI_SETP_DOTLCD_EXTFLASHEMITTESTPERMIT u8: 1→0; values 0/1/0/1 across 01/02/02B/03, so not a stable MS+ES or MOVDC marker. Exact cause requires flash-specific controls.',
    },
    'checksum_proof': {'old': checksum_before, 'new': checksum_after, 'delta': 457,
                       'sum_of_other_byte_deltas': signed_delta},
    'series': series,
    'record_0x4c': {'full_signature_in_both_blobs': False, 'unexplained_changed_bytes': 0},
}
(HERE / 'калибровка_02b.json').write_text(json.dumps(result, ensure_ascii=False, indent=2) + '\n', encoding='utf-8')
with (HERE / 'калибровка_02b.tsv').open('w', encoding='utf-8', newline='') as stream:
    columns = ['name', 'kind', 'id', 'category', 'raw_offset', 'file_offset', 'size', 'old', 'new', 'changed_bytes', 'status_or_labels']
    writer = csv.DictWriter(stream, fieldnames=columns, delimiter='\t', extrasaction='ignore')
    writer.writeheader()
    for row in rows:
        writer.writerow({**row, 'raw_offset': f"0x{row['raw_offset']:X}", 'file_offset': f"0x{row['file_offset']:X}",
                         'changed_bytes': '|'.join(f"0x{change['file_offset']:X}:{change['old']}>{change['new']}" for change in row['changed_bytes']),
                         'status_or_labels': row.get('status') or ','.join(row.get('new_labels', []))})
print('OK: 02 -> 02B CLI diff; 19/19 bytes explained, shutter type calibrated at 0x63A/0x1D8/0x1A8, ISO=125 and flash output identified')
