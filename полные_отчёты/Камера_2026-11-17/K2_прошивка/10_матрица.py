"""Q2: матрица «снимок × изменявшиеся поля» по серии BACKUP-снимков X-H2 5.30.

Перезапускаемый скрипт: автоматически подхватывает новые каталоги в
K1_камера/снимки_серия (04_MS, 02C, 05, 06, 07, 07B, 07C и т.д.), исключает
неуспешные попытки (нет backup.bin или snapshot.json status != complete) и
перезаписывает выходные файлы. Входные блобы только читаются.

Дополнительно (обновление Q2): проверка согласованности меню/output-полей затвора
и выдержки, отметка снимков с устаревшим output, классификация FRONT_CMD_ASSIGN
как контекстного состояния UI и анализ счётчика 0xF6BC (гипотеза перезапуска питания).

Запуск:  python 10_матрица.py [--series КАТАЛОГ] [--map карта_банка.json]

Выход (в K2_прошивка):
  10_матрица.json   — машинная версия: снимки, поля, значения, условия дефекта,
                      согласованность меню/output, гипотеза перезапуска;
  10_матрица.tsv    — снимки × UI-поля (значения);
  10_служебные.tsv  — снимки × служебные поля (отдельно);
  10_матрица.txt    — читаемая версия поля × снимки с подписями и анализом.
"""

import argparse
import hashlib
import json
import re
import struct
import subprocess
import sys
from pathlib import Path

HERE = Path(__file__).resolve().parent
DEFAULT_SERIES = HERE.parent / 'K1_камера' / 'снимки_серия'

# Поля условия дефекта (калиброваны K2, layout current).
F_DRIVE_CH = 'UI_SETP_DOTLCD_CONTINUOUS'          # 0xACE, file 0x68C: 21 = CH
F_DRIVE_CH2 = 'UI_SETP_DOTLCD_CONTINUOUS2'        # 0xACF, file 0x68D: дубликат
F_DRIVE_CURRENT = 'UI_SETP_CONTINUOUS'            # 0x858, file 0x4F8: 0=S, 1=серия
F_SHUTTER_OUTPUT = 'UI_SETP_DOTLCD_SHUTTERTYPE_OUTPUT'  # 0xAB8, file 0x1A8: фактический затвор
F_SHUTTER_MENU = 'UI_SETP_SHUTTER_TYPE'           # 0x827, file 0x63A: выбор меню
F_SHUTTER_DOTLCD = 'UI_SETP_DOTLCD_SHUTTERTYPE'   # 0xAC7, file 0x1D8: копия меню
F_SPEED_OUTPUT = 'UI_SETP_DOTLCD_SHUTERSPEED_OUTPUT'  # 0xAAB, file 0x18C: знаменатель×100
F_SPEED_M = 'UI_SETP_SHUTTER_SPEED_M'             # 0x8A0, file 0x5B2: индекс M
F_SPEED_DISPLAY = 'UI_SETP_DOTLCD_SHUTTERSPEED'   # 0xABB, file 0x681: display-индекс
F_DISP = 'UI_SETP_REC_VIEW'                       # 0xB, file 0x29B: 2=CONTINUOUS, 3=OFF
F_FRONT_CMD = 'UI_SETP_FRONT_CMD_ASSIGN'          # контекстное состояние UI, не настройка
F_HIFREQ = 'UI_SETP_HIFREQ_FLKLESS_SHUTTER_SPEED_M'  # 0x8A9, file 0xC0

SHUTTER_LABELS = {0: 'MS', 1: 'ES', 2: 'MS+ES', 3: 'EF', 4: 'EF+MS', 5: 'EF+MS+ES'}
DRIVE_LABELS = {0: 'S', 21: 'CH', 23: 'CL'}
# Допустимые фактические затворы для комбинированных меню-режимов.
COMBO_MEMBERS = {2: {0, 1}, 4: {3, 0}, 5: {3, 0, 1}}
SPEED_DISPLAY_OFFSET = 2   # display-индекс 0x681 = индекс M 0x5B2 + 2 (когда дисплей активен)
COUNTER_OFFSET = 0xF6BC    # SERVICE_SHUTCOUNT_CANDIDATE, u32; гипотеза: счётчик включений


def natural_key(label):
    return [int(part) if part.isdigit() else part.lower()
            for part in re.split(r'(\d+)', label)]


def run_decoder(*arguments):
    completed = subprocess.run(
        [sys.executable, '-B', str(HERE / 'decode_backup.py'), *map(str, arguments)],
        check=True, capture_output=True, text=True, encoding='utf-8')
    return json.loads(completed.stdout)


def discover(series):
    accepted, excluded = [], []
    for directory in sorted(series.iterdir(), key=lambda p: natural_key(p.name)):
        if not directory.is_dir():
            continue
        blob = directory / 'backup.bin'
        meta_path = directory / 'snapshot.json'
        status = None
        if meta_path.is_file():
            try:
                status = json.loads(meta_path.read_text(encoding='utf-8')).get('status')
            except (OSError, json.JSONDecodeError):
                status = 'unreadable'
        if not blob.is_file():
            excluded.append({'label': directory.name, 'reason': 'no backup.bin', 'status': status})
            continue
        if status is not None and status != 'complete':
            excluded.append({'label': directory.name, 'reason': f'snapshot status {status!r}', 'status': status})
            continue
        accepted.append({'label': directory.name, 'path': blob, 'status': status or 'no_snapshot_json'})
    return accepted, excluded


def field_class(name, scenario_names):
    if name in scenario_names:
        return 'scenario'
    if name == F_FRONT_CMD:
        return 'ui_context'
    if 'MENU_POS' in name:
        return 'menu_navigation'
    if name == 'UI_SETP_SETTING_CHKSUM':
        return 'checksum'
    if name.startswith('UI_SETP_DOTLCD_') or name in ('UI_SETP_DRV_MENU', F_HIFREQ):
        return 'derivative'
    return 'setting'


def speed_text(value):
    if value is None or value == 0:
        return '—'
    return f'1/{value // 100}' if value % 100 == 0 else f'1/{value / 100:g}'


def conditions(settings):
    def value(name):
        item = settings.get(name)
        return item['value'] if item else None

    drive_row = value(F_DRIVE_CH)
    if drive_row is None:
        drive_row = value(F_DRIVE_CH2)
    output = value(F_SHUTTER_OUTPUT)
    speed = value(F_SPEED_OUTPUT)
    disp = value(F_DISP)
    checks = {
        'CH': drive_row == 21,
        'actual_ES': output == 1,
        'speed_le_1_8000': speed is not None and speed >= 800000,
        'DISP_CONTINUOUS': disp == 2,
    }
    return {
        'checks': checks,
        'defect_scenario': all(checks.values()),
        'drive': DRIVE_LABELS.get(drive_row, f'row{drive_row}'),
        'drive_current': value(F_DRIVE_CURRENT),
        'shutter_menu': SHUTTER_LABELS.get(value(F_SHUTTER_MENU), value(F_SHUTTER_MENU)),
        'shutter_dotlcd': SHUTTER_LABELS.get(value(F_SHUTTER_DOTLCD), value(F_SHUTTER_DOTLCD)),
        'shutter_actual': SHUTTER_LABELS.get(output, output),
        'speed_denominator_x100': speed,
        'speed': speed_text(speed),
        'image_disp': {2: 'CONTINUOUS', 3: 'OFF'}.get(disp, disp),
    }


def build_denom_map(snapshots):
    """Индекс M -> знаменатель×100 по «якорным» снимкам со свежим output.

    Якорь: mirror==меню-тип И display-индекс==индекс M+2 (дисплей активен).
    У таких снимков output-поля согласованы с меню, знаменатель достоверен.
    """
    denom = {}
    for s in snapshots:
        v = lambda name: s['settings'].get(name, {}).get('value')
        menu, mirror = v(F_SHUTTER_MENU), v(F_SHUTTER_DOTLCD)
        idx, disp = v(F_SPEED_M), v(F_SPEED_DISPLAY)
        if menu is None or idx is None:
            continue
        if mirror == menu and disp == idx + SPEED_DISPLAY_OFFSET:
            denom.setdefault(idx, v(F_SPEED_OUTPUT))
    return denom


def shutter_consistency(settings, denom_map):
    """Согласованность меню и output-полей затвора/выдержки.

    Устаревший output: mirror!=меню, либо знаменатель!=табличному для индекс M,
    либо фактический затвор не соответствует меню. display-индекс 0x681 —
    вспомогательный (0 = дисплей не активен, не обязательно устаревание).
    """
    v = lambda name: settings.get(name, {}).get('value')
    menu, mirror, actual = v(F_SHUTTER_MENU), v(F_SHUTTER_DOTLCD), v(F_SHUTTER_OUTPUT)
    idx, speed_out, disp_idx = v(F_SPEED_M), v(F_SPEED_OUTPUT), v(F_SPEED_DISPLAY)
    checks = {}
    checks['type_mirror_eq_menu'] = (mirror == menu)
    if menu in COMBO_MEMBERS:
        checks['actual_resolves_menu'] = actual in COMBO_MEMBERS[menu]
    else:
        checks['actual_resolves_menu'] = (actual == menu)
    expected = denom_map.get(idx)
    checks['speed_denom_eq_menu'] = (expected is not None and speed_out == expected)
    checks['speed_denom_known'] = expected is not None
    display_active = disp_idx == idx + SPEED_DISPLAY_OFFSET
    stale = not (checks['type_mirror_eq_menu'] and checks['actual_resolves_menu']
                 and checks['speed_denom_eq_menu'])
    return {
        'checks': checks,
        'stale_output': stale,
        'menu_type': menu, 'mirror_type': mirror, 'actual_type': actual,
        'menu_speed_index': idx, 'speed_output_x100': speed_out,
        'expected_speed_x100': expected,
        'display_index': disp_idx, 'display_index_expected': (idx + SPEED_DISPLAY_OFFSET) if idx is not None else None,
        'display_active': display_active,
        'display_inactive_zero': disp_idx == 0,
    }


def build(series, map_path):
    firmware_map = json.loads(map_path.read_text(encoding='utf-8'))
    scenario_names = set()
    for field in firmware_map['scenario']:
        scenario_names.add(field['name'])
    accepted, excluded = discover(series)
    if not accepted:
        raise ValueError(f'No successful snapshots with backup.bin in {series}')

    snapshots = []
    for item in accepted:
        decoded = run_decoder(item['path'], '--map', map_path)
        data = item['path'].read_bytes()
        settings = decoded['settings']
        service = decoded['service_fields']
        counter_be = struct.unpack_from('>I', data, COUNTER_OFFSET)[0] if len(data) > COUNTER_OFFSET + 4 else None
        counter_le = struct.unpack_from('<I', data, COUNTER_OFFSET)[0] if len(data) > COUNTER_OFFSET + 4 else None
        snapshots.append({
            'label': item['label'], 'source': str(item['path']),
            'sha256': hashlib.sha256(data).hexdigest(), 'file_size': len(data),
            'checksum_valid': decoded['checksum'].get('valid'),
            'settings': settings, 'service_fields': service,
            'conditions': conditions(settings),
            'counter_F6BC': {'be': counter_be, 'le': counter_le},
        })

    denom_map = build_denom_map(snapshots)
    for s in snapshots:
        s['consistency'] = shutter_consistency(s['settings'], denom_map)
        if s['consistency']['stale_output']:
            s['conditions']['stale_output_caveat'] = (
                'output-поля устарели: условия затвор/выдержка по ним недостоверны')

    # Гипотеза перезапуска питания: output-поля и 0xF6BC заморожены между
    # снимками без перезапуска и обновляются при перезапуске.
    output_fields = [F_SHUTTER_OUTPUT, F_SHUTTER_DOTLCD, F_SPEED_OUTPUT, F_SPEED_DISPLAY]
    frozen = []
    for i in range(1, len(snapshots)):
        prev, cur = snapshots[i - 1], snapshots[i]
        sig = lambda s: tuple(s['settings'].get(f, {}).get('value') for f in output_fields)
        if sig(cur) == sig(prev) and cur['counter_F6BC']['be'] == prev['counter_F6BC']['be']:
            frozen.append({'label': cur['label'], 'frozen_from': prev['label']})
            cur['consistency']['frozen_from'] = prev['label']

    labels = [s['label'] for s in snapshots]
    setting_names = set()
    for snapshot in snapshots:
        setting_names |= snapshot['settings'].keys()
    changed = sorted(
        (name for name in setting_names
         if len({s['settings'].get(name, {}).get('value') for s in snapshots}) > 1),
        key=lambda n: int(snapshots[0]['settings'][n]['file_offset']) if n in snapshots[0]['settings'] else 1 << 30)
    included = [name for name in changed if name not in scenario_names]
    scenario_order = [field['name'] for field in firmware_map['scenario']]
    ordered = [name for name in scenario_order if name in setting_names] + included

    service_names = sorted({name for s in snapshots for name in s['service_fields']})
    fields = []
    for name in ordered:
        reference = next(s['settings'][name] for s in snapshots if name in s['settings'])
        fields.append({
            'name': name, 'class': field_class(name, scenario_names), 'kind': 'setting',
            'ui_setp': reference['id'], 'file_offset': f"0x{reference['file_offset']:X}",
            'size': reference['size'],
            'changed': name in changed,
            'values': {s['label']: s['settings'].get(name, {}).get('value') for s in snapshots},
            'labels': {s['label']: s['settings'].get(name, {}).get('value_labels', []) for s in snapshots},
        })
    service_fields = []
    for name in service_names:
        reference = next(s['service_fields'][name] for s in snapshots if name in s['service_fields'])
        service_fields.append({
            'name': name, 'class': 'service', 'kind': 'service',
            'file_offset': f"0x{reference['file_offset']:X}", 'size': reference['size'],
            'changed': len({s['service_fields'].get(name, {}).get('value') for s in snapshots}) > 1,
            'values': {s['label']: s['service_fields'].get(name, {}).get('value') for s in snapshots},
        })

    defect_labels = [s['label'] for s in snapshots if s['conditions']['defect_scenario']]
    control_labels = [label for label in labels if label not in defect_labels]
    pairwise = []
    for defect in defect_labels:
        defect_snapshot = next(s for s in snapshots if s['label'] == defect)
        for control in control_labels:
            control_snapshot = next(s for s in snapshots if s['label'] == control)
            differing = []
            for field in fields + service_fields:
                before = field['values'].get(defect)
                after = field['values'].get(control)
                if before != after:
                    differing.append({'name': field['name'], 'class': field['class'],
                                      'defect_value': before, 'control_value': after})
            failed = [name for name, ok in control_snapshot['conditions']['checks'].items() if not ok]
            pairwise.append({'defect': defect, 'control': control,
                             'control_failed_checks': failed, 'differing_fields': differing})
    common = None
    if pairwise:
        common = sorted(set.intersection(*(
            {row['name'] for row in pair['differing_fields']
             if row['class'] not in ('menu_navigation', 'checksum', 'service', 'ui_context')}
            for pair in pairwise)))

    return {
        'series': str(series), 'layout_mode': 'current', 'labels': labels,
        'excluded': excluded, 'snapshots': [
            {k: v for k, v in s.items() if k not in ('settings', 'service_fields')} | {
                'settings_values': {name: s['settings'].get(name, {}).get('value') for name in ordered},
                'service_values': {name: s['service_fields'].get(name, {}).get('value') for name in service_names},
            } for s in snapshots],
        'fields': fields, 'service_fields': service_fields,
        'defect_labels': defect_labels, 'control_labels': control_labels,
        'pairwise_defect_vs_control': pairwise,
        'common_distinguishing_fields': common,
        'speed_denom_map': {str(k): v for k, v in sorted(denom_map.items())},
        'stale_output_labels': [s['label'] for s in snapshots if s['consistency']['stale_output']],
        'frozen_output_runs': frozen,
        'power_restart_hypothesis': {
            'statement': ('Output/display-поля (0x1A8, 0x1D8, 0x18C, 0x681) и счётчик 0xF6BC '
                          'пересчитываются/сохраняются при перезапуске питания, а не при спуске; '
                          'между перезапусками заморожены. 0xF6BC — вероятно счётчик включений/наработки, не спусков.'),
            'evidence': ('06=07=07B по output-полям и 0xF6BC (без перезапуска); 07C после перезапуска '
                         'обновил output до меню (EF@1/25). Владелец перезапускал питание для 01–06 и 07C, не для 07/07B.'),
            'status': 'гипотеза, подтверждается 07C; semantics 0xF6BC не установлена',
        },
    }


def cell(value, labels):
    if value is None:
        return '—'
    text = str(value)
    if labels:
        text += ' [' + '; '.join(labels) + ']'
    return text


def write_tsv(path, labels, columns, rows):
    lines = ['label\t' + '\t'.join(columns)]
    for label in labels:
        lines.append(label + '\t' + '\t'.join(str(rows[label].get(name, '—')) for name in columns))
    path.write_text('\n'.join(lines) + '\n', encoding='utf-8')


def write_outputs(result, prefix):
    labels = result['labels']
    fields, service = result['fields'], result['service_fields']
    write_tsv(prefix.with_name(prefix.name + '.tsv'), labels,
              [f"{f['name']}@{f['file_offset']}" for f in fields],
              {s['label']: {f['name']: s['settings_values'].get(f['name']) for f in fields} for s in result['snapshots']})
    write_tsv(prefix.with_name('10_служебные.tsv'), labels,
              [f"{f['name']}@{f['file_offset']}" for f in service],
              {s['label']: {f['name']: s['service_values'].get(f['name']) for f in service} for s in result['snapshots']})

    width = max(len(f['name']) for f in fields + service) + 2
    lines = [f"Матрица серии BACKUP X-H2 5.30 (layout current). Снимков: {len(labels)}.",
             'Строки — поля, столбцы — снимки. Служебные поля — в отдельном разделе и в 10_служебные.tsv.', '']
    header = 'поле'.ljust(width) + ''.join(label.ljust(26) for label in labels)
    sections = [
        ('СЦЕНАРНЫЕ ПОЛЯ (условие дефекта)', [f for f in fields if f['class'] == 'scenario']),
        ('ПРОЧИЕ ИЗМЕНИВШИЕСЯ UI-ПОЛЯ', [f for f in fields if f['class'] not in ('scenario', 'ui_context')]),
        ('КОНТЕКСТНОЕ СОСТОЯНИЕ UI (не настройка)', [f for f in fields if f['class'] == 'ui_context']),
        ('СЛУЖЕБНЫЕ ПОЛЯ (не настройки)', service),
    ]
    label_by_name = {}
    for field in fields:
        label_by_name[field['name']] = field['labels']
    for title, group in sections:
        if not group:
            continue
        lines.append(title)
        lines.append(header)
        for field in group:
            row = field['name'].ljust(width)
            for label in labels:
                value = field['values'].get(label)
                text = cell(value, label_by_name.get(field['name'], {}).get(label, []))
                row += text.ljust(26)
            mark = '' if field['changed'] else '  (не менялось)'
            lines.append(row + mark)
        lines.append('')
    lines.append('УСЛОВИЯ ДЕФЕКТА ПО СНИМКАМ (CH + фактический ES + выдержка ≤1/8000 + IMAGE DISP CONTINUOUS)')
    for snapshot in result['snapshots']:
        cond = snapshot['conditions']
        checks = ' '.join(f'{name}={"+" if ok else "−"}' for name, ok in cond['checks'].items())
        verdict = 'СЦЕНАРИЙ ДЕФЕКТА' if cond['defect_scenario'] else 'контроль'
        stale = '  [УСТАРЕВШИЙ OUTPUT]' if snapshot['consistency']['stale_output'] else ''
        lines.append(f"{snapshot['label']}: {verdict}; {checks}; "
                     f"DRIVE={cond['drive']}, затвор меню={cond['shutter_menu']}, факт={cond['shutter_actual']}, "
                     f"выдержка={cond['speed']}, DISP={cond['image_disp']}{stale}")
    lines.append('')
    lines.append('СОГЛАСОВАННОСТЬ МЕНЮ / OUTPUT (затвор и выдержка)')
    lines.append('Проверки: mirror(0x1D8)==меню(0x63A); факт(0x1A8) разрешает меню; знаменатель(0x18C)==табличному для индекс M(0x5B2).')
    lines.append(f"Таблица индекс M -> знаменатель×100 (по якорным снимкам): {result['speed_denom_map']}")
    for snapshot in result['snapshots']:
        c = snapshot['consistency']
        flags = ' '.join(f'{k}={"+" if ok else "−"}' for k, ok in c['checks'].items())
        verdict = 'УСТАРЕВШИЙ OUTPUT' if c['stale_output'] else 'согласован'
        extra = ''
        if c.get('frozen_from'):
            extra = f" (заморожен от {c['frozen_from']})"
        elif c['display_inactive_zero']:
            extra = ' (display-индекс 0x681=0: дисплей не активен)'
        lines.append(f"{snapshot['label']}: {verdict}{extra}; {flags}; "
                     f"меню={c['menu_type']}/{c['menu_speed_index']}, mirror={c['mirror_type']}, факт={c['actual_type']}, "
                     f"speed={c['speed_output_x100']} (ожид {c['expected_speed_x100']}), dispIdx={c['display_index']}")
    lines.append('')
    hyp = result['power_restart_hypothesis']
    lines.append('ГИПОТЕЗА ПЕРЕЗАПУСКА ПИТАНИЯ (output-поля и 0xF6BC)')
    lines.append('  ' + hyp['statement'])
    lines.append('  Доказательство: ' + hyp['evidence'])
    lines.append('  Статус: ' + hyp['status'])
    if result['frozen_output_runs']:
        lines.append('  Замороженные переходы: ' + '; '.join(f"{f['label']} ← {f['frozen_from']}" for f in result['frozen_output_runs']))
    lines.append('  Счётчик 0xF6BC (SERVICE_SHUTCOUNT_CANDIDATE) по снимкам:')
    for snapshot in result['snapshots']:
        cnt = snapshot['counter_F6BC']
        lines.append(f"    {snapshot['label']}: BE={cnt['be']} LE={cnt['le']}")
    lines.append('')
    if result['pairwise_defect_vs_control']:
        lines.append('РАЗЛИЧИЯ ДЕФЕКТ-СНИМОК ↔ КАЖДЫЙ КОНТРОЛЬ (без меню/суммы/служебных/UI-контекста — в JSON полностью)')
        for pair in result['pairwise_defect_vs_control']:
            failed = ', '.join(pair['control_failed_checks']) or 'все условия выполнены'
            lines.append(f"{pair['defect']} ↔ {pair['control']}: у контроля не выполнено: {failed}")
            for row in pair['differing_fields']:
                if row['class'] in ('menu_navigation', 'checksum', 'service', 'ui_context'):
                    continue
                lines.append(f"    {row['name']}: {row['defect_value']} ↔ {row['control_value']}")
        lines.append('')
        lines.append('Поля, различающие дефект со ВСЕМИ контролями одновременно: '
                     + (', '.join(result['common_distinguishing_fields']) or 'нет'))
    if result['excluded']:
        lines.append('')
        lines.append('Исключённые каталоги: ' + '; '.join(f"{e['label']} ({e['reason']})" for e in result['excluded']))
    prefix.with_name(prefix.name + '.txt').write_text('\n'.join(lines) + '\n', encoding='utf-8')
    prefix.with_name(prefix.name + '.json').write_text(
        json.dumps(result, ensure_ascii=False, indent=2) + '\n', encoding='utf-8')


def main(argv=None):
    parser = argparse.ArgumentParser(description='Q2: матрица снимок × изменявшиеся поля BACKUP X-H2 5.30.')
    parser.add_argument('--series', type=Path, default=DEFAULT_SERIES)
    parser.add_argument('--map', type=Path, default=HERE / 'карта_банка.json')
    parser.add_argument('--out', type=Path, default=HERE / '10_матрица')
    args = parser.parse_args(argv)
    result = build(args.series, args.map)
    write_outputs(result, args.out)
    if hasattr(sys.stdout, 'reconfigure'):
        sys.stdout.reconfigure(encoding='utf-8')
    print(f"Снимков: {len(result['labels'])} ({', '.join(result['labels'])})")
    print(f"Изменившихся UI-полей: {sum(f['changed'] for f in result['fields'])}, служебных: {len(result['service_fields'])}")
    for snapshot in result['snapshots']:
        cond = snapshot['conditions']
        stale = ' [УСТАРЕВШИЙ OUTPUT]' if snapshot['consistency']['stale_output'] else ''
        print(f"  {snapshot['label']}: {'ДЕФЕКТ' if cond['defect_scenario'] else 'контроль'} "
              f"(DRIVE={cond['drive']}, факт={cond['shutter_actual']}, {cond['speed']}, DISP={cond['image_disp']}){stale}")
    print(f"Устаревший output: {', '.join(result['stale_output_labels']) or 'нет'}")
    print(f"Исключено: {len(result['excluded'])} ({', '.join(e['label'] for e in result['excluded']) or 'нет'})")
    print(f"Выход: {args.out}.json/.tsv/.txt, 10_служебные.tsv")


if __name__ == '__main__':
    main()
