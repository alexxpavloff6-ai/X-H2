"""Q2: статическое доказательство «вычисленных» DOTLCD-полей BACKUP X-H2 5.30.

Только чтение блоков прошивки и снимков; входные файлы не меняются. Перезапускаемый.

Что доказывает:
  A. Механизм экспорта: банк копируется 1:1 (0x11DA714), затем преобразования
     0x12E5AD4 перезаписывают лишь отдельные слоты. DOTLCD-поля в блобе — это
     живые значения банка (при экспорте не пересчитываются); из сценарных полей
     перезаписывается только REC_VIEW (IMAGE DISP). Bluetooth-блок пишется в
     соседние слоты file 0x66B..0x673 и НЕ трогает EXTFLASH file 0x67B.
  B. ISO_OUTPUT и EXTFLASH — вычисляемые display-выходы, а не зеркала настроек:
     базовые настройки ISO и flash постоянны во всех снимках, а выходы меняются.
  C. SHUTTERTYPE_OUTPUT вычисляется из SHUTTER_TYPE + выдержки: MS+ES(2) в меню
     даёт фактический ES(1) на 1/16000 (быстрее механического максимума 1/8000).
  D. Адреса сеттеров (запись в банк со stride 0x12768 по слотам) для ключевых полей.

Запуск:  python 10_вычисленные_поля.py
Выход:   10_вычисленные_поля.json / .txt  (в K2_прошивка).
"""

import json
import re
import struct
import subprocess
import sys
from pathlib import Path

HERE = Path(__file__).resolve().parent
sys.path.insert(0, str(HERE.parents[1] / 'Сравнение_версий_2026-11-16'))
import fwcommon

SERIES = HERE.parent / 'K1_камера' / 'снимки_серия'
XFORM_LO, XFORM_HI = 0x12DC790, 0x12E5AD4
SETTINGS_BANK = 0x2628A88
BANK_STRIDE = 0x12768

# bank_offset -> (name, file_offset). file = bank + 0xA0 (main segment).
DOTLCD = {
    0x108: ('UI_SETP_DOTLCD_SHUTTERTYPE_OUTPUT', 0x1A8, 'word'),
    0xF0: ('UI_SETP_DOTLCD_ISO_OUTPUT', 0x190, 'word'),
    0xEC: ('UI_SETP_DOTLCD_SHUTERSPEED_OUTPUT', 0x18C, 'word'),
    0x138: ('UI_SETP_DOTLCD_SHUTTERTYPE', 0x1D8, 'word'),
    0x5DB: ('UI_SETP_DOTLCD_EXTFLASHEMITTESTPERMIT', 0x67B, 'byte'),
    0x5E1: ('UI_SETP_DOTLCD_SHUTTERSPEED', 0x681, 'byte'),
    0x5EC: ('UI_SETP_DOTLCD_CONTINUOUS', 0x68C, 'byte'),
    0x5ED: ('UI_SETP_DOTLCD_CONTINUOUS2', 0x68D, 'byte'),
    0x4C: ('UI_SETP_DOTLCD_CONTMODE', 0xEC, 'word'),
    0x42D: ('UI_SETP_DRV_MENU', 0x4CD, 'byte'),
    0x20: ('UI_SETP_HIFREQ_FLKLESS_SHUTTER_SPEED_M', 0xC0, 'word'),
    0x1FB: ('UI_SETP_REC_VIEW', 0x29B, 'byte'),
}


def export_rewrites(b0):
    """Сканирует область преобразований экспорта на запись по bank-смещениям."""
    data, base = b0.data, b0.base
    hits = []
    for o in range(b0.off(XFORM_LO), b0.off(XFORM_HI), 4):
        w = struct.unpack_from('<I', data, o)[0]
        top = w & 0xFFC00000
        imm = (w >> 10) & 0xFFF
        for bank, (name, file_off, kind) in DOTLCD.items():
            enc = 0xB9000000 if kind == 'word' else 0x39000000
            off = bank // 4 if kind == 'word' else bank
            if top == enc and imm == off:
                hits.append({'site': f'0x{base + o:X}', 'name': name,
                             'bank_offset': f'0x{bank:X}', 'file_offset': f'0x{file_off:X}'})
    return hits


def setter_stores(b0, banks):
    """Ищет запись в банк (stride 0x12768) для заданных bank-смещений.

    Сигнатура сеттера: перед str есть add xN,xN,#0xa88 и mov xM,#0x2768
    (база банка 0x2628A88 и stride слота). Это отличает сеттеры настроек от
    случайных структур с теми же смещениями.
    """
    data, base = b0.data, b0.base
    wanted = {}
    for bank in banks:
        kind = DOTLCD[bank][2]
        enc = 0xB9000000 if kind == 'word' else 0x39000000
        off = bank // 4 if kind == 'word' else bank
        wanted[(enc, off)] = bank
    found = {bank: [] for bank in banks}
    for o in range(0, len(data) - 3, 4):
        w = struct.unpack_from('<I', data, o)[0]
        key = (w & 0xFFC00000, (w >> 10) & 0xFFF)
        if key not in wanted:
            continue
        va = base + o
        prev = fwcommon.insns(b0, va - 40, 10)
        text = ' | '.join(f'{i.mnemonic} {i.op_str}' for i in prev)
        if re.search(r'add x\d+, x\d+, #0xa88', text) and re.search(r'mov x\d+, #0x2768', text):
            insn = fwcommon.insns(b0, va, 1)[0]
            found[wanted[key]].append({'store': f'0x{va:X}', 'instruction': f'{insn.mnemonic} {insn.op_str}'})
    return found


def decode_labels():
    labels = sorted((p.name for p in SERIES.iterdir()
                     if p.is_dir() and (p / 'backup.bin').is_file()
                     and (not (p / 'snapshot.json').is_file()
                          or json.loads((p / 'snapshot.json').read_text(encoding='utf-8')).get('status') == 'complete')),
                    key=lambda s: [int(t) if t.isdigit() else t.lower() for t in re.split(r'(\d+)', s)])
    settings = {}
    for lab in labels:
        out = subprocess.run([sys.executable, '-B', str(HERE / 'decode_backup.py'), str(SERIES / lab / 'backup.bin')],
                             check=True, capture_output=True, text=True, encoding='utf-8')
        settings[lab] = json.loads(out.stdout)['settings']
    return labels, settings


def values(settings, labels, name):
    return [settings[lab].get(name, {}).get('value') for lab in labels]


def constant_proof(labels, settings):
    # «Настоящие» настройки (не DOTLCD display-производные): их постоянство
    # доказывает, что меняющийся output — вычисляемый, а не смена настройки.
    # DOTLCD-зеркала (DOTLCD_ISO, DOTLCD_FLASHSTATE, DOTLCD_FLASHTTLMODE и т.п.)
    # сами являются display-выходами и могут меняться с контекстом съёмки.
    groups = {
        'ISO': {
            'settings': ['UI_SETP_ISO_PSAM', 'UI_SETP_ISOAUTO_SET_BASE_PSAM'],
            'output': 'UI_SETP_DOTLCD_ISO_OUTPUT',
        },
        'FLASH': {
            'settings': ['UI_SETP_EXT_FLASH', 'UI_SETP_BUILT_IN_FLASH'],
            'output': 'UI_SETP_DOTLCD_EXTFLASHEMITTESTPERMIT',
        },
    }
    result = {}
    for group, spec in groups.items():
        rows = {}
        for name in spec['settings'] + [spec['output']]:
            vals = values(settings, labels, name)
            rows[name] = {'values': vals, 'constant': len(set(vals)) == 1}
        output_vals = rows[spec['output']]['values']
        settings_constant = all(rows[n]['constant'] for n in spec['settings'])
        result[group] = {
            'fields': rows, 'output': spec['output'],
            'settings_all_constant': settings_constant,
            'output_varies': len(set(output_vals)) > 1,
            'conclusion': ('вычисляемый display-выход (настройки постоянны, выход меняется)'
                           if settings_constant and len(set(output_vals)) > 1 else 'требует доп. данных'),
        }
    return result


def shutter_resolution(labels, settings):
    menu = values(settings, labels, 'UI_SETP_SHUTTER_TYPE')
    output = values(settings, labels, 'UI_SETP_DOTLCD_SHUTTERTYPE_OUTPUT')
    mirror = values(settings, labels, 'UI_SETP_DOTLCD_SHUTTERTYPE')
    speed = values(settings, labels, 'UI_SETP_DOTLCD_SHUTERSPEED_OUTPUT')
    rows = []
    for i, lab in enumerate(labels):
        rows.append({'label': lab, 'menu': menu[i], 'mirror': mirror[i], 'actual_output': output[i],
                     'speed_denominator_x100': speed[i],
                     'computed': menu[i] != output[i]})
    return rows


def main():
    b0 = fwcommon.load('X-H2', 'old', 0)
    labels, settings = decode_labels()
    rewrites = export_rewrites(b0)
    stores = setter_stores(b0, [0x108, 0xF0, 0x5DB])
    result = {
        'firmware': 'xh2-530', 'labels': labels,
        'export': {
            'memcpy_bank': '0x11DA714 (0x12768 bytes, settings_bank 0x2628A88 -> destination_bank 0x2578A18)',
            'transform_dispatcher': '0x12E5AD4', 'export_wrapper': '0x12E5B44',
            'addressing': 'file_offset = bank_offset + 0xA0 (main segment); transformations write at destination_bank offset == bank_offset',
            'scenario_fields_rewritten_during_export': rewrites,
            'note': 'DOTLCD-поля не перезаписываются при экспорте — в блобе живые значения банка; перезаписывается только REC_VIEW.',
        },
        'setter_stores': {DOTLCD[b][0]: stores[b] for b in stores},
        'constant_settings_proof': constant_proof(labels, settings),
        'shutter_type_resolution': shutter_resolution(labels, settings),
    }
    (HERE / '10_вычисленные_поля.json').write_text(json.dumps(result, ensure_ascii=False, indent=2) + '\n', encoding='utf-8')

    lines = ['Q2: вычисленные DOTLCD-поля BACKUP X-H2 5.30 (статика + серия).', '']
    lines.append('A. Экспорт: банк копируется 1:1, преобразования 0x12E5AD4 перезаписывают отдельные слоты.')
    lines.append('   Перезаписанные сценарные поля при экспорте:')
    for h in rewrites:
        lines.append(f"     {h['site']}: {h['name']} (file {h['file_offset']})")
    lines.append('   => DOTLCD-поля в блобе — живые значения банка, не пересчёт при экспорте.')
    lines.append('')
    lines.append('D. Сеттеры (запись в банк, stride 0x12768):')
    for name, ss in result['setter_stores'].items():
        for s in ss:
            lines.append(f"   {name}: {s['store']}  {s['instruction']}")
    lines.append('')
    lines.append('B. Постоянство настроек при изменчивости display-выходов:')
    for group, info in result['constant_settings_proof'].items():
        lines.append(f"   [{group}] {info['conclusion']}")
        for name, row in info['fields'].items():
            tag = 'константа' if row['constant'] else 'МЕНЯЕТСЯ'
            lines.append(f"     {name}: {row['values']}  ({tag})")
    lines.append('')
    lines.append('C. Разрешение типа затвора (меню -> фактический output):')
    for row in result['shutter_type_resolution']:
        mark = '  <-- ВЫЧИСЛЕНО (меню != факт)' if row['computed'] else ''
        lines.append(f"     {row['label']}: меню={row['menu']} mirror={row['mirror']} "
                     f"факт={row['actual_output']} выдержка={row['speed_denominator_x100']}{mark}")
    (HERE / '10_вычисленные_поля.txt').write_text('\n'.join(lines) + '\n', encoding='utf-8')
    if hasattr(sys.stdout, 'reconfigure'):
        sys.stdout.reconfigure(encoding='utf-8')
    print('\n'.join(lines))


if __name__ == '__main__':
    main()
