import json
import struct
import subprocess
import sys
import tempfile
from pathlib import Path

import decode_backup

HERE = Path(__file__).resolve().parent
MAP = decode_backup.load_map(HERE / 'карта_банка.json')
FIELDS = {int(row['id']): row for row in MAP['entries_current']}
assert MAP['scenario_layout_mode'] == 'current'
for setting_id in (0x858, 0x827, 0xB, 0x8A0, 0xACE, 0xACF, 0xAAB, 0xABB):
    assert setting_id in FIELDS


def set_checksum(raw):
    struct.pack_into('<I', raw, 0x3C, 0)
    spans = MAP['layout']['checksum']['supported_spans'][hex(len(raw))]
    checksum = sum(sum(raw[start:end]) for start, end in spans) & 0xFFFFFFFF
    struct.pack_into('<I', raw, 0x3C, checksum)


def make_raw(length, changed):
    raw = bytearray(length)
    values = {
        0x858: 1 if changed else 0, 0x827: 3 if changed else 1,
        0xB: 2 if changed else 3, 0xACE: 21 if changed else 0, 0xACF: 21 if changed else 0,
        0x8A0: 67 if changed else 38, 0xAAB: 800000 if changed else 2500,
        0xABB: 69 if changed else 40, 0x8A9: 600 if changed else 1,
        0x874: 1 if changed else 0, 0xA70: 1 if changed else 0,
        0xAA8: 1 if changed else 0, 0xAB8: 3 if changed else 1,
    }
    for setting_id, value in values.items():
        entry = FIELDS[setting_id]
        offset = int(entry['blob_offset'], 0)
        raw[offset:offset + entry['size']] = value.to_bytes(entry['size'], 'little')
    struct.pack_into('<H', raw, 0xF614, 8611 if changed else 7429)
    struct.pack_into('<H', raw, 0xF67C, 72 if changed else 64776)
    return raw


def run(*arguments):
    completed = subprocess.run(
        [sys.executable, '-B', str(HERE / 'decode_backup.py'), *map(str, arguments)],
        check=True, capture_output=True, text=True, encoding='utf-8')
    return json.loads(completed.stdout)


with tempfile.TemporaryDirectory(prefix='.decoder_check_', dir=HERE) as temporary:
    directory = Path(temporary)
    old_directory = directory / '01_синтетика'
    old_directory.mkdir()
    length = 0x112D4
    old_raw = make_raw(length, False)
    new_raw = make_raw(length, True)
    ranges = decode_backup.unknown_ranges(length, decode_backup.coverage_for_mode(MAP, 'current'))
    unknown_offset = next(start for start, end in ranges if end > start)
    old_raw[unknown_offset] = 0xA5
    new_raw[unknown_offset] = 0x5A
    record_offset = max(ranges, key=lambda pair: pair[1] - pair[0])[0]
    assert next(end for start, end in ranges if start == record_offset) - record_offset >= 0x78
    for raw, flag in ((old_raw, 1), (new_raw, 0)):
        struct.pack_into('<HBBI', raw, record_offset, 0x4C, 1, 0, 0x158)
        struct.pack_into('<I', raw, record_offset + 0x6C, flag)
        struct.pack_into('<I', raw, record_offset + 0x74, 2)
        set_checksum(raw)
    header = bytearray(0xA8)
    header[8:20] = decode_backup.MAGIC
    old_path = old_directory / 'backup.bin'
    new_path = directory / 'new.bin'
    old_path.write_bytes(header + old_raw)
    new_path.write_bytes(header + new_raw)

    decoded = run(old_directory)
    assert decoded['layout_mode'] == 'current'
    assert decoded['container']['magic_offset'] == 8
    assert decoded['container']['payload_offset'] == 0xA8
    assert decoded['payload_length'] == length
    assert decoded['checksum']['valid'] is True
    assert decoded['settings']['UI_SETP_CONTINUOUS']['raw_offset'] == 0x450
    assert decoded['settings']['UI_SETP_CONTINUOUS']['file_offset'] == 0x4F8
    assert decoded['settings']['UI_SETP_CONTINUOUS']['value'] == 0
    assert decoded['settings']['UI_SETP_SHUTTER_TYPE']['raw_offset'] == 0x592
    assert decoded['settings']['UI_SETP_SHUTTER_TYPE']['value_labels'] == ['ES']
    assert decoded['settings']['UI_SETP_REC_VIEW']['value_labels'] == ['OFF']
    assert decoded['settings']['UI_SETP_REC_VIEW']['value'] == 3
    assert decoded['settings']['UI_SETP_REC_VIEW']['usb_value_candidates'] == [0]
    assert decoded['settings']['UI_SETP_DOTLCD_CONTINUOUS']['value_labels'] == ['S / STILL IMAGE']
    assert decoded['settings']['UI_SETP_SHUTTER_SPEED_M']['value_labels'] == ['1/25 s']
    assert decoded['service_fields']['SERVICE_SHUTCOUNT_CANDIDATE']['value'] == 7429
    assert decoded['service_fields']['SERVICE_VOLATILE_U16_F67C']['value'] == 64776
    candidate = decoded['record_0x4c_candidates'][0]
    assert candidate['file_offset'] == 0xA8 + record_offset
    assert candidate['serialized_8byte_header']['u32_le'] == 1
    assert candidate['ram_16byte_container']['u32_le'] == 2

    compared = run('--diff', old_path, new_path)
    assert compared['changed']['UI_SETP_CONTINUOUS']['new']['value'] == 1
    assert compared['changed']['UI_SETP_SHUTTER_TYPE']['new']['value_labels'] == ['EF']
    assert compared['changed']['UI_SETP_REC_VIEW']['new']['value_labels'] == ['CONTINUOUS']
    assert compared['changed']['UI_SETP_DOTLCD_CONTINUOUS']['new']['value_labels'] == ['CH HIGH SPEED BURST']
    assert compared['changed']['UI_SETP_SHUTTER_SPEED_M']['new']['value_labels'] == ['1/8000 s']
    assert compared['changed_service_count'] == 2
    changed_unknown = {change['raw_offset']: change for row in compared['unknown_changed_ranges'] for change in row['changes']}
    assert changed_unknown[unknown_offset] == {'raw_offset': unknown_offset, 'old': '0xA5', 'new': '0x5A'}
    assert compared['record_0x4c_candidates']['new'][0]['serialized_8byte_header']['u32_le'] == 0
    assert compared['new']['checksum']['valid'] is True
    assert compared['changed_byte_count'] >= compared['explained_changed_byte_count']

    raw_path = directory / 'raw.bin'
    raw_path.write_bytes(old_raw)
    raw_decoded = run(raw_path)
    assert raw_decoded['container']['payload_offset'] == 0
    assert raw_decoded['settings']['UI_SETP_SHUTTER_TYPE']['file_offset'] == 0x592
    mode0 = run('--layout', 'mode0', raw_path)
    assert 'UI_SETP_CONTINUOUS' not in mode0['settings']
    assert mode0['unavailable_settings']['UI_SETP_CONTINUOUS']['bank_offset'] == 0x1168C
    assert mode0['settings']['UI_SETP_REC_VIEW']['raw_offset'] == 0x1F3

    short_raw = make_raw(0xF6D4, False)
    set_checksum(short_raw)
    short_path = directory / 'short.bin'
    short_path.write_bytes(short_raw)
    short_decoded = run(short_path)
    assert short_decoded['checksum']['valid'] is True
    assert short_decoded['settings']['UI_SETP_CONTINUOUS']['raw_offset'] == 0x450
    assert short_decoded['settings']['UI_SETP_REC_VIEW']['value_labels'] == ['OFF']

result = {
    'all_checks_passed': True, 'real_camera_blob_used': False,
    'checks': ['CLI single decode from a one-blob directory', 'CLI diff of two blobs',
               'current Drive raw 0x450/file 0x4F8 and DOTLCD row labels',
               'current Shutter Type raw 0x592/file 0x63A', 'current M shutter index raw 0x50A/file 0x5B2',
               'IMAGE DISP raw 0x1F3 and serialized values 2/3', 'legacy mode0 high fields excluded from export',
               'X-BACKUP0100 at header+8 and 0xA8 payload offset', 'raw payload input',
               'named settings and two service-field diffs', 'unknown-byte diff and changed-byte accounting',
               'record 0x4C signature and both flag candidates', '0xF6D4 and 0x112D4 checksum variants'],
    'note': 'Synthetic markers verify decoder mechanics only. Real-camera verification is in 08_проверка_реальных.py and реальные_блобы.json.',
}
(HERE / 'проверка_декодера.json').write_text(json.dumps(result, ensure_ascii=False, indent=2) + '\n', encoding='utf-8')
print('OK: CLI current/legacy decode and diff, slot-7 offsets, service metadata, raw+container input, unknown bytes, record 0x4C and checksums')
