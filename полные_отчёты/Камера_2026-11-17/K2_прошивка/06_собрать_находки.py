import json
from pathlib import Path

HERE = Path(__file__).resolve().parent
chain = json.loads((HERE / 'цепочка_0x4c.json').read_text(encoding='utf-8'))
backup = json.loads((HERE / 'backup.json').read_text(encoding='utf-8'))
settings = json.loads((HERE / 'настройки.json').read_text(encoding='utf-8'))
link = json.loads((HERE / 'связь_0x4c.json').read_text(encoding='utf-8'))
bank_map = json.loads((HERE / 'карта_банка.json').read_text(encoding='utf-8'))
decoder_check = json.loads((HERE / 'проверка_декодера.json').read_text(encoding='utf-8'))
real = json.loads((HERE / 'реальные_блобы.json').read_text(encoding='utf-8'))
calibration = json.loads((HERE / 'калибровка_02b.json').read_text(encoding='utf-8'))
report = (HERE / 'отчёт.md').read_text(encoding='utf-8')
assert chain['all_checks_passed']
assert all(row['ok'] for row in backup['checks'])
assert settings['property_list']['count'] == 278
assert not link['direct_static_link_to_scenario']
assert decoder_check['all_checks_passed'] and not decoder_check['real_camera_blob_used']
assert real['all_checks_passed'] and real['real_camera_blob_used'] and not real['camera_accessed_by_this_script']
assert real['totals']['changed_bytes'] == real['totals']['explained_changed_bytes'] == 27
assert real['totals']['unexplained_changed_bytes'] == 0
assert not real['record_0x4c']['full_signature_in_required_blobs']
assert calibration['all_checks_passed'] and calibration['real_camera_blob_used'] and not calibration['camera_accessed_by_this_script']
assert calibration['totals']['changed_bytes'] == calibration['totals']['explained_changed_bytes'] == 19
assert calibration['totals']['unexplained_changed_bytes'] == 0
assert not calibration['record_0x4c']['full_signature_in_both_blobs']
assert calibration['shutter_type_calibration']['current_menu']['file'] == '0x63A'
assert calibration['shutter_type_calibration']['dotlcd_menu']['file'] == '0x1D8'
assert calibration['shutter_type_calibration']['actual_output']['file'] == '0x1A8'
assert backup['record_0x4c_inclusion']['status'] == 'not_observed_in_real_01_02'
assert bank_map['scenario_layout_mode'] == 'current'
scenario = {field['scenario_name']: field for field in bank_map['scenario']}
assert scenario['DRIVE MODE / CH HIGH SPEED BURST']['blob_offset'] == '0x450'
assert scenario['SHUTTER TYPE / current value in 02']['blob_offset'] == '0x592'
assert scenario['IMAGE DISP / CONTINUOUS']['blob_offset'] == '0x1F3'
assert scenario['SHUTTER SPEED / 1/8000']['blob_offset'] == '0x50A'
for required in ('0x14CF354', '0x31053F8', '0x3105440', '0x31085A8', '0x3108AA8', '0x4C33F14', '0x4A458',
                 '0xD201', '0x500D', '0xD03C', '0xD103', '0x158', 'payload+0x64',
                 '0x450', '0x592', '0x50A', '0xF7E8', '0xF875', '0x112D4', 'decode_backup.py'):
    assert required in report, required

result = {
    'task': 'K2: X-H2 5.30 — BACKUP decoder, record 0x4C/MOVDC',
    'firmware': 'X-H2 5.30', 'camera_used': False, 'status': 'complete_with_explicit_unknowns',
    'addresses_5_30': chain['addresses'], 'layout': chain['layout'],
    'backup': {
        'export': backup['ptp_export'], 'serialization': backup['serialization'],
        'record_0x4c_inclusion': backup['record_0x4c_inclusion'],
    },
    'backup_decoder': {
        'map_statistics': bank_map['statistics'], 'segment_layout': bank_map['layout']['export_segments'],
        'current_map': bank_map['layout']['current_map'], 'mode_selector': bank_map['layout']['mode_selector'],
        'scenario_layout_mode': 'current', 'scenario_fields': bank_map['scenario'],
        'legacy_scenario_candidates': bank_map['legacy_scenario_candidates'],
        'enum_values': bank_map['enum_values'], 'derived_value_labels': bank_map['derived_value_labels'],
        'runtime_metadata': bank_map['runtime_metadata'],
        'cli': ['python decode_backup.py <backup.bin|directory>',
                'python decode_backup.py --diff <old.bin> <new.bin>',
                'python decode_backup.py --layout mode0 <backup.bin>'],
        'outputs': ['settings', 'service_fields', 'scenario_fields', 'changed', 'changed_service_fields',
                    'changed_byte_count', 'explained_changed_byte_count', 'unexplained_changed_byte_count',
                    'diff_ranges', 'unknown_ranges', 'unknown_changed_ranges', 'checksum', 'record_0x4c_candidates'],
        'synthetic_verification': decoder_check,
        'real_blob_validated': True,
        'real_verification': real,
        'calibration_02b': calibration,
    },
    'settings': settings['settings'],
    'record_link': {
        'direct_static_link_to_scenario': link['direct_static_link_to_scenario'],
        'conclusion': link['conclusion'], 'record_get_site': '0x31053F8',
        'record_rpc_sites_with_id_0x4c': 0, 'state_flag_writers': ['0x31085A8', '0x3108AA8'],
        'snapshot_expectations': link['snapshot_expectations'],
        'real_backup_conclusion': real['record_0x4c'],
        'calibration_02b_conclusion': calibration['record_0x4c'],
    },
    'owner_protocol': {
        'conditions': ['CH HIGH SPEED BURST', 'MECHANICAL+ELECTRONIC with actual ES', '1/8000 or faster', 'IMAGE DISP=CONTINUOUS'],
        'steps': [
            'DRIVE button → CH HIGH SPEED BURST',
            'A SHOOTING SETTING → SHUTTER TYPE → MECHANICAL + ELECTRONIC',
            'M mode → 1/8000 or faster; verify ES on the display',
            'D SET UP → SCREEN SET-UP → IMAGE DISP. → CONTINUOUS',
            'Shoot a short burst and observe LCD during the burst and continuous review',
            'Repeat with S, MS, 1/250 and DISP OFF as one-factor controls',
        ],
        'evidence_to_capture': ['menu photos', 'full LCD photo and close-up', 'live view vs review vs saved file',
                                'repeat count and CH rate', 'repeat-baseline noise control'],
        'real_blob_label_mismatch': real['owner_label_mismatch'],
    },
    'verification': {
        'chain_instruction_checks': len(chain['checks']), 'backup_checks': len(backup['checks']),
        'map_ids_total': bank_map['statistics']['ids_total'],
        'serialized_fields_current': bank_map['statistics']['serialized_fields_current'],
        'serialized_fields_mode0': bank_map['statistics']['serialized_fields_mode0'],
        'serialized_fields_mode1': bank_map['statistics']['serialized_fields_mode1'],
        'decoder_synthetic_checks': len(decoder_check['checks']),
        'real_changed_bytes': real['totals']['changed_bytes'],
        'real_explained_changed_bytes': real['totals']['explained_changed_bytes'],
        'real_unexplained_changed_bytes': real['totals']['unexplained_changed_bytes'],
        'real_changed_ui_fields': real['totals']['changed_ui_fields'],
        'real_changed_service_fields': real['totals']['changed_service_fields'],
        'calibration_02b_changed_bytes': calibration['totals']['changed_bytes'],
        'calibration_02b_explained_changed_bytes': calibration['totals']['explained_changed_bytes'],
        'calibration_02b_unexplained_changed_bytes': calibration['totals']['unexplained_changed_bytes'],
        'record_get_calls_with_id_0x4c': 1, 'record_rpc_calls_with_id_0x4c': 0,
        'pending_flag_writes': 0, 'current_flag_reads': 2, 'state_flag_writes': 2,
        'usb_properties_advertised': {'0xD201': True, '0x500D': True, '0xD03C': False, '0xD103': False},
    },
    'remaining_unknowns': [
        'The exact name and units of SERVICE_VOLATILE_U16_F67C are unresolved; it is volatile and outside the checksum spans.',
        'SERVICE_SHUTCOUNT_CANDIDATE is a probable monotonic shutter counter, but its binding to UI_SETP 0x172 is not statically proven.',
        'A theoretical service projection of a separate record scalar into BACKUP is not categorically excluded, but neither a full record nor a guard candidate is observed.',
        'The manual/auto cause of ISO output 125 and the exact flash-state cause of EXTFLASHEMITTESTPERMIT changes require dedicated controls.',
        'Which runtime value the record service assigns to payload+0x64 in each scenario.',
        'Full value semantics of all save transformations and all compatibility container variants.',
        'The actual LCD manifestation on the owner camera; no camera test was performed by K2.',
    ],
    'artifacts': {
        'report': 'отчёт.md',
        'chain': ['01_цепочка_0x4c.py', 'цепочка_0x4c.txt', 'цепочка_0x4c.json'],
        'backup': ['02_backup.py', 'backup.txt', 'backup.json'],
        'settings': ['03_настройки.py', 'настройки.txt', 'настройки.json'],
        'record_link': ['04_связь_0x4c.py', 'связь_0x4c.txt', 'связь_0x4c.json'],
        'bank_map': ['05_карта_банка.py', 'карта_банка.json', 'карта_банка.tsv'],
        'decoder': ['decode_backup.py', '07_проверка_декодера.py', 'проверка_декодера.json'],
        'real_validation': ['08_проверка_реальных.py', 'реальные_блобы.json', 'реальный_diff.tsv'],
        'calibration_02b': ['09_калибровка_02b.py', 'калибровка_02b.json', 'калибровка_02b.tsv'],
        'aggregator': '06_собрать_находки.py',
    },
}
(HERE / 'находки.json').write_text(json.dumps(result, ensure_ascii=False, indent=2) + '\n', encoding='utf-8')
print('OK: saved находки.json with current map, real 27/27 and calibration 19/19-byte validation')
