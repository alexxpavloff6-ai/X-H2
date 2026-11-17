import argparse
import hashlib
import json
import struct
import sys
from pathlib import Path

HERE = Path(__file__).resolve().parent
MAGIC = b'X-BACKUP0100'
BLOB_SUFFIXES = {'.bin', '.blob', '.backup', '.bak', '.dat'}
MAX_BLOB_BYTES = 16 * 1024 * 1024
RECORD_SIGNATURE_PREFIX = b'\x4c\x00'


def load_map(path):
    result = json.loads(path.read_text(encoding='utf-8'))
    if result['layout']['firmware'] != 'xh2-530':
        raise ValueError(f"Expected the X-H2 5.30 map, got {result['layout']['firmware']}")
    return result


def resolve_blob(argument):
    path = Path(argument).expanduser().resolve()
    if path.is_file():
        return path
    if not path.is_dir():
        raise ValueError(f'Not a file or directory: {path}')
    direct = sorted(p for p in path.iterdir() if p.is_file() and p.suffix.lower() in BLOB_SUFFIXES)
    candidates = direct or sorted(p for p in path.rglob('*') if p.is_file() and p.suffix.lower() in BLOB_SUFFIXES)
    if len(candidates) != 1:
        names = '\n'.join(str(p) for p in candidates[:20])
        raise ValueError(f'Directory must contain exactly one BACKUP blob; found {len(candidates)}.\n{names}')
    return candidates[0]


def read_blob(argument):
    path = resolve_blob(argument)
    size = path.stat().st_size
    if not size or size > MAX_BLOB_BYTES:
        raise ValueError(f'Unexpected blob size {size}: {path}; maximum accepted is {MAX_BLOB_BYTES}')
    return path, path.read_bytes()


def split_container(data, payload_offset=None):
    warnings = []
    if payload_offset is not None:
        if not 0 <= payload_offset <= len(data):
            raise ValueError(f'Payload offset {payload_offset:#x} is outside the {len(data):#x}-byte file')
        return data[payload_offset:], {
            'detected': False, 'payload_offset': payload_offset,
            'format': 'manual payload offset', 'magic_offset': None,
        }, warnings
    magic_offset = data.find(MAGIC, 0, min(len(data), 0x100))
    if magic_offset < 0:
        warnings.append('X-BACKUP0100 was not found in the first 0x100 bytes; assuming that the file starts with the raw main payload.')
        return data, {
            'detected': False, 'payload_offset': 0, 'format': 'raw payload assumed',
            'magic_offset': None, 'header_sha256': None,
        }, warnings
    container_offset = magic_offset - 8 if magic_offset >= 8 else 0
    start = container_offset + 0xA8
    if start > len(data):
        raise ValueError(f'Container ends at {start:#x}, beyond the {len(data):#x}-byte file')
    if magic_offset not in (0, 8):
        warnings.append(f'Magic is at unusual offset {magic_offset:#x}; inferred container start {container_offset:#x} from the firmware header+8 layout.')
    return data[start:], {
        'detected': True, 'payload_offset': start, 'format': 'X-BACKUP0100 + 0xA8-byte container',
        'magic_offset': magic_offset, 'container_offset': container_offset,
        'header_length': start - container_offset,
        'header_sha256': hashlib.sha256(data[container_offset:start]).hexdigest(),
    }, warnings


def checksum_info(payload, layout):
    rule = layout['checksum']
    result = {
        'validator': rule['validator'], 'payload_length': len(payload),
        'status': 'unsupported_length', 'accepted_lengths': rule['accepted_lengths'],
        'stored_u32': None, 'calculated_u32': None, 'valid': None,
    }
    if len(payload) < 0x40:
        result['status'] = 'truncated_header'
        return result
    result['stored_u32'] = struct.unpack_from('<I', payload, rule['raw_destination'])[0]
    spans = rule['supported_spans'].get(hex(len(payload)))
    if spans is None:
        result['note'] = 'No safe checksum span is assigned to this payload length; see the 0x12E5D9C buffer-contract warning in the map.'
        return result
    work = bytearray(payload)
    struct.pack_into('<I', work, rule['raw_destination'], 0)
    calculated = sum(sum(work[start:end]) for start, end in spans) & 0xFFFFFFFF
    result.update({
        'status': 'checked', 'calculated_u32': calculated,
        'valid': calculated == result['stored_u32'], 'spans': spans,
        'algorithm': 'zero u32 at raw+0x3C; sum unsigned bytes in spans modulo 2^32',
    })
    return result


def merged_coverage(length, entries):
    intervals = []
    for entry in entries:
        if entry['blob_offset'] is None:
            continue
        start = int(entry['blob_offset'], 0)
        end = start + entry['size']
        if start >= 0 and end <= length:
            intervals.append((start, end))
    intervals.sort()
    merged = []
    for start, end in intervals:
        if merged and start <= merged[-1][1]:
            merged[-1] = (merged[-1][0], max(end, merged[-1][1]))
        else:
            merged.append((start, end))
    return merged


def unknown_ranges(length, entries):
    result, cursor = [], 0
    for start, end in merged_coverage(length, entries) + [(length, length)]:
        if cursor < start:
            result.append((cursor, start))
        cursor = max(cursor, end)
    return result


def value_interpretation(entry, value, firmware_map):
    labels, usb_values = [], []
    enum = firmware_map.get('enum_values', {}).get(str(entry['id']))
    if enum:
        column = enum.get('serialized_column', 'raw')
        matching = [row for row in enum['rows'] if row[column] == value]
        labels = sorted({row['label'] for row in matching if row['label'] is not None})
        usb_values = sorted({row['usb'] for row in matching if row['usb'] is not None})
    derived = firmware_map.get('derived_value_labels', {}).get(str(entry['id']), {})
    derived_label = derived.get(str(value))
    if derived_label:
        labels = sorted(set(labels) | {derived_label})
    return labels, usb_values


def record_candidates(data, payload_offset):
    candidates, start = [], 0
    needle_size = 8
    while True:
        offset = data.find(RECORD_SIGNATURE_PREFIX, start)
        if offset < 0:
            break
        start = offset + 1
        if offset + needle_size > len(data):
            continue
        record_id, record_type, record_flags, size = struct.unpack_from('<HBBI', data, offset)
        if record_id != 0x4C or size != 0x158:
            continue
        item = {
            'status': 'signature_candidate_only', 'file_offset': offset,
            'raw_offset': offset - payload_offset, 'record_type': record_type,
            'record_flags': record_flags, 'payload_size': size,
        }
        for label, relative in (('serialized_8byte_header', 0x6C), ('ram_16byte_container', 0x74)):
            flag_offset = offset + relative
            item[label] = {
                'flag_file_offset': flag_offset,
                'flag_raw_offset': flag_offset - payload_offset,
                'u32_le': struct.unpack_from('<I', data, flag_offset)[0] if flag_offset + 4 <= len(data) else None,
            }
        candidates.append(item)
    return candidates


def entries_for_mode(firmware_map, layout_mode):
    if layout_mode not in ('current', 'mode0', 'mode1'):
        raise ValueError(f'Unknown layout mode: {layout_mode}')
    return firmware_map[f'entries_{layout_mode}']


def coverage_for_mode(firmware_map, layout_mode):
    return entries_for_mode(firmware_map, layout_mode) + firmware_map.get('runtime_metadata', [])


def decode_runtime_metadata(payload, container, entries):
    result = {}
    for entry in entries:
        item = dict(entry)
        raw_offset = int(entry['blob_offset'], 0)
        item.update({'raw_offset': raw_offset, 'file_offset': container['payload_offset'] + raw_offset,
                     'bank_offset': int(entry['bank_offset'], 0)})
        if raw_offset < 0 or raw_offset + entry['size'] > len(payload):
            item['status'] = 'truncated payload'
        else:
            value = int.from_bytes(payload[raw_offset:raw_offset + entry['size']], 'little', signed=False)
            item.update({'value': value, 'value_hex': f'0x{value:X}'})
        result[entry['name']] = item
    return result


def decode(argument, firmware_map, payload_offset=None, layout_mode='current'):
    path, data = read_blob(argument)
    payload, container, warnings = split_container(data, payload_offset)
    entries = entries_for_mode(firmware_map, layout_mode)
    settings, unavailable = {}, {}
    for entry in entries:
        size = entry['size']
        name = entry['name'] if entry['name'] not in settings else f"{entry['name']}@{entry['ui_setp']}"
        if entry['blob_offset'] is None:
            unavailable[name] = {'id': entry['ui_setp'], 'raw_offset': None,
                                 'bank_offset': int(entry['bank_offset'], 0),
                                 'reason': 'outside the two exported BACKUP segments'}
            continue
        raw_offset = int(entry['blob_offset'], 0)
        if raw_offset < 0 or raw_offset + size > len(payload):
            unavailable[name] = {'id': entry['ui_setp'], 'raw_offset': raw_offset,
                                 'reason': 'truncated payload'}
            continue
        value = int.from_bytes(payload[raw_offset:raw_offset + size], 'little', signed=False)
        labels, usb_values = value_interpretation(entry, value, firmware_map)
        item = {
            'id': entry['ui_setp'], 'name': entry['name'], 'all_names': entry['all_names'],
            'raw_offset': raw_offset, 'file_offset': container['payload_offset'] + raw_offset,
            'bank_offset': int(entry['bank_offset'], 0), 'segment': entry['segment'],
            'size': size, 'type': entry['type'], 'layout_mode': layout_mode,
            'value': value, 'value_hex': f'0x{value:X}', 'value_labels': labels,
            'usb_value_candidates': usb_values, 'case': entry['case'],
            'instruction_address': entry['instruction_address'], 'instruction': entry['instruction'],
        }
        if entry['signed_access']:
            item['signed_value'] = value - (1 << (size * 8)) if value & (1 << (size * 8 - 1)) else value
        settings[name] = item
    scenario = []
    by_id = {int(item['id'], 0): item for item in settings.values()}
    candidates_by_id = {entry['id']: entry for entry in entries}
    for field in firmware_map['scenario']:
        ids = field['id'] if isinstance(field['id'], list) else [field['id']]
        item = next((by_id[setting_id] for setting_id in ids if setting_id in by_id), None)
        candidate = next((candidates_by_id[setting_id] for setting_id in ids if setting_id in candidates_by_id), None)
        row = {
            'scenario_name': field['scenario_name'], 'ui_setp': field.get('ui_setp', [f'0x{x:X}' for x in ids]),
            'raw_offset': candidate['blob_offset'] if candidate else None,
            'bank_offset': candidate['bank_offset'] if candidate else None,
            'expected_raw_value': field.get('scenario_raw_value'),
            'expected_usb_value': field.get('scenario_usb_value'),
        }
        if item:
            row.update({'file_offset': item['file_offset'], 'value': item['value'],
                        'value_hex': item['value_hex'], 'value_labels': item['value_labels']})
            if field.get('scenario_raw_value') is not None:
                row['matches_expected'] = item['value'] == field['scenario_raw_value']
        else:
            row['status'] = 'outside exported segments in this layout mode' if candidate else 'no direct backup field'
            row['reason'] = field.get('reason', field.get('raw_value_note'))
        if field.get('raw_value_note'):
            row['raw_value_note'] = field['raw_value_note']
        scenario.append(row)
    coverage = coverage_for_mode(firmware_map, layout_mode)
    ranges = [{'raw_offset': start, 'file_offset': container['payload_offset'] + start,
               'end': end, 'length': end - start, 'hex': payload[start:end].hex()}
              for start, end in unknown_ranges(len(payload), coverage)]
    if layout_mode == 'current':
        warnings.append('Current slot-7 map validated on real 01/02 BACKUP blobs; selector-0 and selector-1 current maps are identical.')
    else:
        warnings.append(f'{layout_mode} is a legacy slot-0 custom-bank layout, not the validated current-settings layout.')
    record_hits = record_candidates(data, container['payload_offset'])
    record_note = ('A signature is only a candidate; verify the full diff before assigning a flag.' if record_hits else
                   'No full record 0x4C signature occurs in this blob. A separate scalar projection cannot be excluded by signature absence alone.')
    return {
        'mode': 'decode', 'layout_mode': layout_mode, 'source': str(path), 'file_size': len(data),
        'firmware_map': firmware_map['layout']['firmware'],
        'map_statistics': firmware_map['statistics'], 'container': container,
        'payload_length': len(payload), 'checksum': checksum_info(payload, firmware_map['layout']),
        'scenario_fields': scenario, 'settings': settings, 'unavailable_settings': unavailable,
        'service_fields': decode_runtime_metadata(payload, container, firmware_map.get('runtime_metadata', [])),
        'unknown_ranges': ranges, 'record_0x4c_candidates': record_hits,
        'record_0x4c_note': record_note,
        'warnings': warnings,
    }


def difference_ranges(old, new):
    result, start = [], None
    for index in range(min(len(old), len(new))):
        if old[index] != new[index] and start is None:
            start = index
        elif old[index] == new[index] and start is not None:
            result.append((start, index))
            start = None
    if start is not None:
        result.append((start, min(len(old), len(new))))
    if len(old) != len(new):
        result.append((min(len(old), len(new)), max(len(old), len(new))))
    return result


def diff(old_argument, new_argument, firmware_map, payload_offset=None, layout_mode='current'):
    old_path, old_data = read_blob(old_argument)
    new_path, new_data = read_blob(new_argument)
    old_payload, old_container, old_warnings = split_container(old_data, payload_offset)
    new_payload, new_container, new_warnings = split_container(new_data, payload_offset)
    old = decode(old_path, firmware_map, payload_offset, layout_mode)
    new = decode(new_path, firmware_map, payload_offset, layout_mode)
    changed = {}
    for name in old['settings'].keys() & new['settings'].keys():
        before, after = old['settings'][name], new['settings'][name]
        if before['value'] != after['value']:
            changed[name] = {'old': before, 'new': after}
    changed_service = {}
    for name in old['service_fields'].keys() & new['service_fields'].keys():
        before, after = old['service_fields'][name], new['service_fields'][name]
        if before.get('value') != after.get('value'):
            changed_service[name] = {'old': before, 'new': after}
    maximum = max(len(old_payload), len(new_payload))
    coverage = coverage_for_mode(firmware_map, layout_mode)
    unknown = []
    for start, end in unknown_ranges(maximum, coverage):
        changes = []
        for offset in range(start, end):
            before = old_payload[offset] if offset < len(old_payload) else None
            after = new_payload[offset] if offset < len(new_payload) else None
            if before != after:
                changes.append({'raw_offset': offset,
                                'old': None if before is None else f'0x{before:02X}',
                                'new': None if after is None else f'0x{after:02X}'})
        unknown.append({
            'raw_offset': start, 'end': end, 'length': end - start,
            'old_file_offset': old_container['payload_offset'] + start if start < len(old_payload) else None,
            'new_file_offset': new_container['payload_offset'] + start if start < len(new_payload) else None,
            'changed_byte_count': len(changes), 'changes': changes,
        })
    scenario_changes = {}
    old_scenario = {row['scenario_name']: row for row in old['scenario_fields']}
    new_scenario = {row['scenario_name']: row for row in new['scenario_fields']}
    for name in old_scenario.keys() | new_scenario.keys():
        if old_scenario.get(name) != new_scenario.get(name):
            scenario_changes[name] = {'old': old_scenario.get(name), 'new': new_scenario.get(name)}
    ranges = [{'raw_offset': start, 'end': end, 'length': end - start,
               'old_file_offset': old_container['payload_offset'] + start,
               'new_file_offset': new_container['payload_offset'] + start}
              for start, end in difference_ranges(old_payload, new_payload)]
    unknown_changed = [row for row in unknown if row['changed_byte_count']]
    changed_byte_count = sum(row['length'] for row in ranges)
    unexplained_byte_count = sum(row['changed_byte_count'] for row in unknown_changed)
    record_hits = {
        'old': record_candidates(old_data, old_container['payload_offset']),
        'new': record_candidates(new_data, new_container['payload_offset']),
    }
    record_note = ('Candidates are not proof of inclusion; require a stable, scenario-specific candidate.' if any(record_hits.values()) else
                   'Neither blob contains the full record 0x4C signature. All changed bytes are still checked for an unexplained scalar candidate.')
    warnings = ['Raw mapped values are decoded after firmware backup transformations; they are not guaranteed to equal live-UI or USB values.']
    if layout_mode == 'current':
        warnings.append('Current slot-7 map validated on real 01/02 BACKUP blobs; legacy custom copies are not used.')
    else:
        warnings.append(f'{layout_mode} is a legacy slot-0 custom-bank layout, not the validated current-settings layout.')
    return {
        'mode': 'diff', 'layout_mode': layout_mode, 'firmware_map': firmware_map['layout']['firmware'],
        'old': {'source': str(old_path), 'container': old_container, 'payload_length': len(old_payload),
                'checksum': old['checksum'], 'warnings': old_warnings},
        'new': {'source': str(new_path), 'container': new_container, 'payload_length': len(new_payload),
                'checksum': new['checksum'], 'warnings': new_warnings},
        'changed': changed, 'changed_count': len(changed),
        'changed_service_fields': changed_service, 'changed_service_count': len(changed_service),
        'changed_byte_count': changed_byte_count,
        'explained_changed_byte_count': changed_byte_count - unexplained_byte_count,
        'unexplained_changed_byte_count': unexplained_byte_count,
        'only_in_old': sorted(old['settings'].keys() - new['settings'].keys()),
        'only_in_new': sorted(new['settings'].keys() - old['settings'].keys()),
        'scenario_changes': scenario_changes, 'diff_ranges': ranges,
        'unknown_ranges': unknown,
        'unknown_changed_ranges': unknown_changed,
        'record_0x4c_candidates': record_hits,
        'record_0x4c_note': record_note,
        'warnings': warnings,
    }


def main(argv=None):
    parser = argparse.ArgumentParser(description='Read-only X-H2 5.30 BACKUP decoder and named-setting diff.')
    parser.add_argument('inputs', nargs='+', help='One blob/directory, or old and new blobs/directories with --diff')
    parser.add_argument('--diff', action='store_true', help='Compare exactly two blobs: --diff OLD NEW')
    parser.add_argument('--layout', choices=('current', 'mode0', 'mode1'), default='current',
                        help='current is the real-blob-validated slot-7 map (default); mode0/mode1 are legacy custom-bank alternatives')
    parser.add_argument('--map', type=Path, default=HERE / 'карта_банка.json', help='Static map generated by 05_карта_банка.py')
    parser.add_argument('--payload-offset', type=lambda text: int(text, 0), help='Override main-payload file offset (for example 0 or 0xA8)')
    args = parser.parse_args(argv)
    if len(args.inputs) > 2 or (args.diff and len(args.inputs) != 2):
        parser.error('Use one input for decode or exactly two inputs for diff')
    try:
        firmware_map = load_map(args.map)
        if args.diff or len(args.inputs) == 2:
            result = diff(args.inputs[0], args.inputs[1], firmware_map, args.payload_offset, args.layout)
        else:
            result = decode(args.inputs[0], firmware_map, args.payload_offset, args.layout)
    except (OSError, ValueError, KeyError, json.JSONDecodeError) as error:
        parser.error(str(error))
    if hasattr(sys.stdout, 'reconfigure'):
        sys.stdout.reconfigure(encoding='utf-8')
    print(json.dumps(result, ensure_ascii=False, indent=2))


if __name__ == '__main__':
    main()
