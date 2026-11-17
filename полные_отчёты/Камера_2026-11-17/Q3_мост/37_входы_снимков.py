# -*- coding: utf-8 -*-
"""Q3 3-й круг, шаг 37: реальные входы конфигураций из BACKUP-блобов серии.
Переиспользует decode_backup.py и карту банка K2 (только чтение блобов)."""
import json
import sys
from pathlib import Path

HERE = Path(__file__).resolve().parent
K2 = HERE.parent / 'K2_прошивка'
SERIES = HERE.parent / 'K1_камера' / 'снимки_серия'
sys.path.insert(0, str(K2))
import decode_backup  # noqa: E402

fmap = decode_backup.load_map(K2 / 'карта_банка.json')

FIELDS = {
    'shutter_menu': 'UI_SETP_SHUTTER_TYPE',                 # 0x63A
    'shutter_actual': 'UI_SETP_DOTLCD_SHUTTERTYPE_OUTPUT',  # 0x1A8
    'shutter_dotlcd': 'UI_SETP_DOTLCD_SHUTTERTYPE',         # 0x1D8
    'continuous': 'UI_SETP_CONTINUOUS',                     # 0x4F8
    'drive_ch': 'UI_SETP_DOTLCD_CONTINUOUS',                # 0x68C (21=CH)
    'drive_ch2': 'UI_SETP_DOTLCD_CONTINUOUS2',              # 0x68D
    'speed_m_index': 'UI_SETP_SHUTTER_SPEED_M',             # 0x5B2
    'speed_output': 'UI_SETP_DOTLCD_SHUTERSPEED_OUTPUT',    # 0x18C (знаменатель x100)
    'rec_view': 'UI_SETP_REC_VIEW',                         # 0x29B (2=CONT,3=OFF)
}
SHUTTER = {0: 'MS', 1: 'ES', 2: 'MS+ES', 3: 'EF', 4: 'EF+MS', 5: 'EF+MS+ES'}

rows = []
for d in sorted(SERIES.iterdir()):
    blob = d / 'backup.bin'
    if not blob.is_file():
        continue
    meta = d / 'snapshot.json'
    status = None
    if meta.is_file():
        try:
            status = json.loads(meta.read_text(encoding='utf-8')).get('status')
        except Exception:
            status = 'unreadable'
    if status is not None and status != 'complete':
        continue
    dec = decode_backup.decode(str(blob), fmap)
    s = dec['settings']
    row = {'label': d.name, 'status': status}
    for key, name in FIELDS.items():
        item = s.get(name)
        row[key] = item['value'] if item else None
        row[key + '_off'] = f"0x{item['file_offset']:X}" if item else None
    row['shutter_menu_label'] = SHUTTER.get(row['shutter_menu'], row['shutter_menu'])
    row['shutter_actual_label'] = SHUTTER.get(row['shutter_actual'], row['shutter_actual'])
    sp = row['speed_output']
    row['speed_text'] = (f'1/{sp // 100}' if sp and sp % 100 == 0 else (f'1/{sp / 100:g}' if sp else '—'))
    row['defect_backup'] = (row['drive_ch'] == 21 and row['shutter_actual'] == 1
                            and sp is not None and sp >= 800000 and row['rec_view'] == 2)
    rows.append(row)

(HERE / '3круг_входы_снимков.json').write_text(json.dumps(rows, ensure_ascii=False, indent=2) + '\n', encoding='utf-8')
# печать таблицы
hdr = ['label', 'menu', 'actual', 'CONT', 'CH(68C)', 'spdM(5B2)', 'speed(18C)', 'REC_VIEW', 'defectBACKUP']
print(' | '.join(hdr))
for r in rows:
    print(' | '.join(str(x) for x in [r['label'], r['shutter_menu_label'], r['shutter_actual_label'],
                                      r['continuous'], r['drive_ch'], r['speed_m_index'],
                                      f"{r['speed_output']}({r['speed_text']})", r['rec_view'], r['defect_backup']]))
