import argparse
import hashlib
import json
from pathlib import Path


DEFAULT_BASELINE = '01_база'
DEFAULT_SCENARIO = '02_CH_ES_8000_CONT'
DEFAULT_CONTROLS = ['03_S', '04_MS', '05_1-250', '06_DISP_OFF', '07_база_повтор']


def load_snapshots(root):
    snapshots = {}
    for directory in sorted(root.iterdir(), key=lambda p: p.name):
        path = directory / 'snapshot.json'
        if not directory.is_dir() or not path.exists():
            continue
        with open(path, encoding='utf-8') as f:
            snapshot = json.load(f)
        label = snapshot.get('label', directory.name)
        if label in snapshots:
            raise ValueError('duplicate snapshot label: %s' % label)
        snapshots[label] = {'directory': directory, 'data': snapshot}
    if len(snapshots) < 2:
        raise ValueError('at least two snapshot directories with snapshot.json are required')
    return snapshots


def properties(snapshot):
    result = {}
    for prop in snapshot['data'].get('properties', []):
        value = prop.get('value', {})
        result[prop['code']] = {
            'response': value.get('response'),
            'data_hex': value.get('data_hex'),
            'transport_error': value.get('transport_error'),
            'decoded': prop.get('value_decoded'),
            'candidates': prop.get('value_candidates'),
        }
    return result


def value_key(value):
    if value is None:
        return None
    return (value.get('response'), value.get('data_hex'), value.get('transport_error'))


def display_value(value, full=False):
    if value is None:
        return '—'
    if value.get('response') != '0x2001':
        return value.get('response') or ('transport error' if value.get('transport_error') else '—')
    text = value.get('data_hex') or ''
    if not full and len(text) > 66:
        text = text[:64] + '…'
    decoded = value.get('decoded')
    if isinstance(decoded, (str, int, float)) and len(text) <= 66:
        return '%s (%s)' % (text, decoded)
    return text or '0 bytes'


def ranges(offsets):
    result = []
    start = previous = None
    for offset in offsets:
        if start is None:
            start = previous = offset
        elif offset == previous + 1:
            previous = offset
        else:
            result.append([start, previous])
            start = previous = offset
    if start is not None:
        result.append([start, previous])
    return result


def pair_changed_ranges(left, right):
    result = []
    start = previous = None
    count = 0
    limit = max(len(left), len(right))
    for offset in range(limit):
        a = left[offset] if offset < len(left) else None
        b = right[offset] if offset < len(right) else None
        if a == b:
            if start is not None:
                result.append([start, previous])
                start = previous = None
            continue
        count += 1
        if start is None:
            start = previous = offset
        elif offset == previous + 1:
            previous = offset
        else:
            result.append([start, previous])
            start = previous = offset
    if start is not None:
        result.append([start, previous])
    return count, result


def format_ranges(items, hexadecimal=True):
    if not items:
        return '—'
    parts = []
    for start, end in items:
        if hexadecimal:
            part = '0x%X' % start if start == end else '0x%X–0x%X' % (start, end)
        else:
            part = str(start) if start == end else '%d–%d' % (start, end)
        parts.append(part)
    return ', '.join(parts)


def load_backups(snapshots):
    backups = {}
    metadata = {}
    for label, item in snapshots.items():
        path = item['directory'] / 'backup.bin'
        if path.exists():
            data = path.read_bytes()
            backups[label] = data
            metadata[label] = {
                'size': len(data), 'sha256': hashlib.sha256(data).hexdigest(),
                'manifest': item['data'].get('backup', {}),
            }
        else:
            metadata[label] = {
                'size': None, 'sha256': None,
                'status': item['data'].get('backup', {}).get('status', 'not_present'),
            }
    return backups, metadata


def compare(snapshots, baseline, scenario, controls):
    labels = list(snapshots)
    for required in [baseline, scenario, *controls]:
        if required not in labels:
            raise ValueError('required snapshot is missing: %s' % required)
    prop_maps = {label: properties(item) for label, item in snapshots.items()}
    all_codes = sorted({code for mapping in prop_maps.values() for code in mapping}, key=lambda x: int(x, 16))
    variable_codes = [
        code for code in all_codes
        if len({value_key(prop_maps[label].get(code)) for label in labels}) > 1
    ]
    property_rows = []
    for code in variable_codes:
        row = {'code': code, 'values': {}}
        for label in labels:
            row['values'][label] = prop_maps[label].get(code)
        property_rows.append(row)

    pair_property_changes = {}
    for i, left in enumerate(labels):
        for right in labels[i + 1:]:
            changed = [
                code for code in all_codes
                if value_key(prop_maps[left].get(code)) != value_key(prop_maps[right].get(code))
            ]
            pair_property_changes['%s | %s' % (left, right)] = changed

    base_map = prop_maps[baseline]
    scenario_map = prop_maps[scenario]
    strict_properties = []
    scenario_only_properties = []
    for code in all_codes:
        base_value = value_key(base_map.get(code))
        scenario_value = value_key(scenario_map.get(code))
        control_values = [value_key(prop_maps[label].get(code)) for label in controls]
        if base_value is None or scenario_value is None or base_value == scenario_value:
            continue
        if any(value is None for value in control_values):
            continue
        record = {
            'code': code,
            'baseline': base_map.get(code),
            'scenario': scenario_map.get(code),
            'controls': {label: prop_maps[label].get(code) for label in controls},
        }
        if all(value == base_value for value in control_values):
            strict_properties.append(record)
        if all(value != scenario_value for value in control_values):
            scenario_only_properties.append(record)

    noise_properties = [
        code for code in all_codes
        if value_key(prop_maps[baseline].get(code)) != value_key(prop_maps['07_база_повтор'].get(code))
    ]
    backups, backup_metadata = load_backups(snapshots)
    backup_pairwise = {}
    backup_labels = [label for label in labels if label in backups]
    for i, left in enumerate(backup_labels):
        for right in backup_labels[i + 1:]:
            count, changed_ranges = pair_changed_ranges(backups[left], backups[right])
            backup_pairwise['%s | %s' % (left, right)] = {
                'changed_bytes': count, 'ranges': changed_ranges,
                'left_size': len(backups[left]), 'right_size': len(backups[right]),
            }

    variable_offsets = []
    variable_values = {}
    if len(backups) >= 2:
        max_size = max(len(data) for data in backups.values())
        for offset in range(max_size):
            values = {
                label: (backups[label][offset] if offset < len(backups[label]) else None)
                for label in backup_labels
            }
            if len(set(values.values())) > 1:
                variable_offsets.append(offset)
                variable_values[offset] = values

    required_backups = [baseline, scenario, *controls]
    unique_possible = all(label in backups for label in required_backups)
    strict_bytes = []
    scenario_only_bytes = []
    if unique_possible:
        for offset in variable_offsets:
            base_value = backups[baseline][offset] if offset < len(backups[baseline]) else None
            scenario_value = backups[scenario][offset] if offset < len(backups[scenario]) else None
            control_values = {
                label: (backups[label][offset] if offset < len(backups[label]) else None)
                for label in controls
            }
            if base_value is None or scenario_value is None or base_value == scenario_value:
                continue
            if any(value is None for value in control_values.values()):
                continue
            record = {
                'offset': offset, 'baseline': base_value, 'scenario': scenario_value,
                'controls': control_values,
            }
            if all(value == base_value for value in control_values.values()):
                strict_bytes.append(record)
            if all(value != scenario_value for value in control_values.values()):
                scenario_only_bytes.append(record)

    backup_noise = backup_pairwise.get('%s | %s' % (baseline, '07_база_повтор'), {})
    if not backup_noise:
        backup_noise = backup_pairwise.get('%s | %s' % ('07_база_повтор', baseline), {})
    return {
        'labels': labels,
        'baseline': baseline,
        'scenario': scenario,
        'controls': controls,
        'property_maps': prop_maps,
        'variable_properties': property_rows,
        'pair_property_changes': pair_property_changes,
        'strict_properties': strict_properties,
        'scenario_only_properties': scenario_only_properties,
        'baseline_repeat_noise_properties': noise_properties,
        'backups': backups,
        'backup_metadata': backup_metadata,
        'backup_pairwise': backup_pairwise,
        'backup_variable_offsets': variable_offsets,
        'backup_variable_values': variable_values,
        'strict_bytes': strict_bytes,
        'scenario_only_bytes': scenario_only_bytes,
        'backup_baseline_repeat_noise': backup_noise,
        'definitions': {
            'strict': '02 differs from 01; every control 03–07 has exactly the 01 value/byte; missing values disqualify.',
            'scenario_only': '02 differs from 01 and no control has the 02 value/byte; controls need not equal 01; missing values disqualify.',
        },
    }


def write_outputs(result, output):
    output.parent.mkdir(parents=True, exist_ok=True)
    output.mkdir(exist_ok=False)
    labels = result['labels']
    with open(output / 'properties.tsv', 'x', encoding='utf-8', newline='') as f:
        f.write('property\t' + '\t'.join(labels) + '\n')
        for row in result['variable_properties']:
            values = [display_value(row['values'].get(label), full=True).replace('\t', ' ').replace('\n', ' ') for label in labels]
            f.write(row['code'] + '\t' + '\t'.join(values) + '\n')

    with open(output / 'backup_bytes.tsv', 'x', encoding='utf-8', newline='') as f:
        backup_labels = [label for label in labels if label in result['backups']]
        f.write('offset_dec\toffset_hex\t' + '\t'.join(backup_labels) + '\n')
        for offset in result['backup_variable_offsets']:
            values = result['backup_variable_values'][offset]
            rendered = [('%02X' % values[label]) if values[label] is not None else '' for label in backup_labels]
            f.write('%d\t0x%X\t%s\n' % (offset, offset, '\t'.join(rendered)))

    with open(output / 'backup_unique.tsv', 'x', encoding='utf-8', newline='') as f:
        controls = result['controls']
        f.write('class\toffset_dec\toffset_hex\tbaseline\tscenario\t' + '\t'.join(controls) + '\n')
        for class_name, key in [('strict', 'strict_bytes'), ('scenario_only', 'scenario_only_bytes')]:
            for row in result[key]:
                values = ['%02X' % row['baseline'], '%02X' % row['scenario']]
                values.extend('%02X' % row['controls'][label] for label in controls)
                f.write('%s\t%d\t0x%X\t%s\n' % (
                    class_name, row['offset'], row['offset'], '\t'.join(values)))

    serializable = {
        'labels': labels,
        'baseline': result['baseline'],
        'scenario': result['scenario'],
        'controls': result['controls'],
        'definitions': result['definitions'],
        'pair_property_changes': result['pair_property_changes'],
        'variable_properties': result['variable_properties'],
        'strict_properties': result['strict_properties'],
        'scenario_only_properties': result['scenario_only_properties'],
        'baseline_repeat_noise_properties': result['baseline_repeat_noise_properties'],
        'backup_metadata': result['backup_metadata'],
        'backup_pairwise': result['backup_pairwise'],
        'backup_variable_offsets_ranges': ranges(result['backup_variable_offsets']),
        'strict_backup_offsets': [row['offset'] for row in result['strict_bytes']],
        'strict_backup_ranges': ranges([row['offset'] for row in result['strict_bytes']]),
        'scenario_only_backup_offsets': [row['offset'] for row in result['scenario_only_bytes']],
        'scenario_only_backup_ranges': ranges([row['offset'] for row in result['scenario_only_bytes']]),
        'backup_baseline_repeat_noise': result['backup_baseline_repeat_noise'],
    }
    with open(output / 'diff.json', 'x', encoding='utf-8') as f:
        json.dump(serializable, f, ensure_ascii=False, indent=2)
        f.write('\n')

    lines = [
        '# Сравнение снимков X-H2',
        '',
        'Порядок: ' + ', '.join('`%s`' % label for label in labels) + '.',
        '',
        'Класс **strict**: сценарий 02 отличается от базы 01, а все контроли 03–07 совпадают с 01. '
        'Класс **scenario_only**: значение/байт 02 не повторяется ни в одном контроле, но контроль не обязан совпадать с 01. '
        'Пропущенные/ошибочные значения не считаются доказательством уникальности.',
        '',
        '## Изменившиеся свойства',
        '',
    ]
    if result['variable_properties']:
        lines.append('| Свойство | ' + ' | '.join(labels) + ' |')
        lines.append('|---|' + '|'.join(['---'] * len(labels)) + '|')
        for row in result['variable_properties']:
            values = [display_value(row['values'].get(label)).replace('|', '\\|') for label in labels]
            lines.append('| `%s` | %s |' % (row['code'], ' | '.join(values)))
    else:
        lines.append('Изменений значений свойств не обнаружено.')
    lines.extend(['', '## Кандидаты, уникальные для сценария 02: свойства', ''])
    for title, key in [('Strict', 'strict_properties'), ('Scenario-only', 'scenario_only_properties')]:
        lines.append('### %s' % title)
        lines.append('')
        rows = result[key]
        if not rows:
            lines.append('Нет.')
        else:
            lines.append('| Свойство | 01 | 02 | ' + ' | '.join(result['controls']) + ' |')
            lines.append('|---|---|---|' + '|'.join(['---'] * len(result['controls'])) + '|')
            for row in rows:
                values = [display_value(row['baseline']), display_value(row['scenario'])]
                values.extend(display_value(row['controls'][label]) for label in result['controls'])
                lines.append('| `%s` | %s |' % (row['code'], ' | '.join(values)))
        lines.append('')
    lines.extend([
        'Шум `01_база` ↔ `07_база_повтор` по свойствам: ' +
        (', '.join('`%s`' % x for x in result['baseline_repeat_noise_properties']) or 'не обнаружен') + '.',
        '',
        '## BACKUP: наличие и размеры',
        '',
        '| Снимок | Размер | SHA-256 / состояние |',
        '|---|---:|---|',
    ])
    for label in labels:
        meta = result['backup_metadata'][label]
        state = meta.get('sha256') or meta.get('status') or meta.get('manifest', {}).get('status', '')
        size = str(meta['size']) if meta.get('size') is not None else '—'
        lines.append('| `%s` | %s | `%s` |' % (label, size, state))
    lines.extend(['', '## BACKUP: попарные различия', ''])
    if result['backup_pairwise']:
        lines.extend(['| Пара | Изменено байт | Диапазоны (смещения от 0) |', '|---|---:|---|'])
        for pair, row in result['backup_pairwise'].items():
            lines.append('| `%s` | %d | %s |' % (pair, row['changed_bytes'], format_ranges(row['ranges'])))
    else:
        lines.append('Меньше двух BACKUP-блобов: побайтовое сравнение недоступно.')
    strict_ranges = ranges([row['offset'] for row in result['strict_bytes']])
    scenario_only_ranges = ranges([row['offset'] for row in result['scenario_only_bytes']])
    lines.extend([
        '',
        '## BACKUP: кандидаты, уникальные для сценария 02',
        '',
        '**Strict:** %d байт; диапазоны: %s.' % (len(result['strict_bytes']), format_ranges(strict_ranges)),
        '',
        '**Scenario-only:** %d байт; диапазоны: %s.' % (len(result['scenario_only_bytes']), format_ranges(scenario_only_ranges)),
        '',
        'Шум BACKUP `01_база` ↔ `07_база_повтор`: %s байт; диапазоны: %s.' % (
            result['backup_baseline_repeat_noise'].get('changed_bytes', '—'),
            format_ranges(result['backup_baseline_repeat_noise'].get('ranges', []))),
        '',
        'Полные значения всех изменяющихся байтов — `backup_bytes.tsv`; значения уникальных кандидатов — '
        '`backup_unique.tsv`; попарные списки свойств и диапазоны — `diff.json`. '
        'Совпадение по контролям — кандидат на поле/флаг, но не доказательство его семантики.',
        '',
    ])
    with open(output / 'отчёт_сравнения.md', 'x', encoding='utf-8') as f:
        f.write('\n'.join(lines))


def main():
    parser = argparse.ArgumentParser(description='Compare read-only X-H2 snapshots and isolate scenario-02 changes')
    parser.add_argument('snapshots_root', type=Path)
    parser.add_argument('output', type=Path, help='new output directory; must not exist')
    parser.add_argument('--baseline', default=DEFAULT_BASELINE)
    parser.add_argument('--scenario', default=DEFAULT_SCENARIO)
    parser.add_argument('--controls', nargs='+', default=DEFAULT_CONTROLS)
    args = parser.parse_args()
    snapshots = load_snapshots(args.snapshots_root)
    result = compare(snapshots, args.baseline, args.scenario, args.controls)
    write_outputs(result, args.output)
    print('Compared %d snapshots; output: %s' % (len(snapshots), args.output))
    print('Strict property candidates: %d; strict BACKUP bytes: %d' % (
        len(result['strict_properties']), len(result['strict_bytes'])))
    print('Scenario-only property candidates: %d; scenario-only BACKUP bytes: %d' % (
        len(result['scenario_only_properties']), len(result['scenario_only_bytes'])))


if __name__ == '__main__':
    main()
