# -*- coding: utf-8 -*-
"""Q3 4-й круг, шаг 45: ссылка на диспетчер 0x14F72C0 (function pointer);
реальные входы новых снимков 07/07B/07C/08/08B."""
import json
import sys
from pathlib import Path

HERE = Path(__file__).resolve().parent
K2 = HERE.parent / 'K2_прошивка'
SERIES = HERE.parent / 'K1_камера' / 'снимки_серия'
sys.path.insert(0, str(HERE))
sys.path.insert(0, str(K2))
from q3common import load, adrp_refs, dis  # noqa: E402
import decode_backup  # noqa: E402

b0 = load('X-H2', 'old', 0)
b1 = load('X-H2', 'old', 1)
out = []
for idx, b in ((0, b0), (1, b1)):
    refs = adrp_refs(b, 0x14F72C0, window=12)
    out.append(f'=== adrp_refs на 0x14F72C0 block{idx}: {len(refs)} ===')
    for r in refs:
        out.append('  ' + r['insn'])
out.append('')

fmap = decode_backup.load_map(K2 / 'карта_банка.json')
FIELDS = {'shutter_menu': 'UI_SETP_SHUTTER_TYPE', 'shutter_actual': 'UI_SETP_DOTLCD_SHUTTERTYPE_OUTPUT',
          'continuous': 'UI_SETP_CONTINUOUS', 'drive_ch': 'UI_SETP_DOTLCD_CONTINUOUS',
          'speed_m_index': 'UI_SETP_SHUTTER_SPEED_M', 'speed_output': 'UI_SETP_DOTLCD_SHUTERSPEED_OUTPUT',
          'rec_view': 'UI_SETP_REC_VIEW'}
SHUTTER = {0: 'MS', 1: 'ES', 2: 'MS+ES', 3: 'EF'}
new_labels = ['07_база_повтор', '07B_база_повтор', '07C_база_повтор', '08_1-500', '08B_1-500']
rows = []
for lab in new_labels:
    blob = SERIES / lab / 'backup.bin'
    if not blob.is_file():
        continue
    dec = decode_backup.decode(str(blob), fmap)
    s = dec['settings']
    row = {'label': lab}
    for k, name in FIELDS.items():
        it = s.get(name)
        row[k] = it['value'] if it else None
    row['menu_lbl'] = SHUTTER.get(row['shutter_menu'], row['shutter_menu'])
    row['actual_lbl'] = SHUTTER.get(row['shutter_actual'], row['shutter_actual'])
    sp = row['speed_output']
    row['speed_text'] = f'1/{sp // 100}' if sp and sp % 100 == 0 else (f'1/{sp / 100:g}' if sp else '—')
    rows.append(row)
out.append('=== реальные входы новых снимков ===')
for r in rows:
    out.append(f"  {r['label']}: menu={r['menu_lbl']} actual={r['actual_lbl']} CH={r['drive_ch']} "
               f"CONT={r['continuous']} spdM={r['speed_m_index']} speed={r['speed_output']}({r['speed_text']}) REC_VIEW={r['rec_view']}")
text = '\n'.join(out)
(HERE / '4круг_новые_снимки.txt').write_text(text + '\n', encoding='utf-8')
(HERE / '4круг_новые_снимки.json').write_text(json.dumps(rows, ensure_ascii=False, indent=2) + '\n', encoding='utf-8')
print(text)
