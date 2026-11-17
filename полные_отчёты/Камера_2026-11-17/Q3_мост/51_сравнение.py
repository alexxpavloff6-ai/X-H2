# -*- coding: utf-8 -*-
"""Q3 4-й круг, шаг 51: сравнение VM-флага на реальных входах снимков с предсказанием.
Расширение 43: все снимки серии, для 08-11 — сравнение с предсказание_порога.json."""
import json
import sys
from pathlib import Path

HERE = Path(__file__).resolve().parent
K2 = HERE.parent / 'K2_прошивка'
SERIES = HERE.parent / 'K1_камера' / 'снимки_серия'
sys.path.insert(0, str(HERE))
sys.path.insert(0, str(K2))
from q3common import load  # noqa: E402
import decode_backup  # noqa: E402
from unicorn import Uc, UC_ARCH_ARM64, UC_MODE_LITTLE_ENDIAN  # noqa: E402
from unicorn.arm64_const import (UC_ARM64_REG_SP, UC_ARM64_REG_LR, UC_ARM64_REG_X0,  # noqa: E402
                                 UC_ARM64_REG_X1, UC_ARM64_REG_X2, UC_ARM64_REG_X3,
                                 UC_ARM64_REG_X4, UC_ARM64_REG_X5)

b0 = load('X-H2', 'old', 0)
b1 = load('X-H2', 'old', 1)
fmap = decode_backup.load_map(K2 / 'карта_банка.json')
pred = json.loads((HERE / 'предсказание_порога.json').read_text(encoding='utf-8'))
FIELDS = {'shutter_menu': 'UI_SETP_SHUTTER_TYPE', 'shutter_actual': 'UI_SETP_DOTLCD_SHUTTERTYPE_OUTPUT',
          'continuous': 'UI_SETP_CONTINUOUS', 'drive_ch': 'UI_SETP_DOTLCD_CONTINUOUS',
          'speed_m_index': 'UI_SETP_SHUTTER_SPEED_M', 'speed_output': 'UI_SETP_DOTLCD_SHUTERSPEED_OUTPUT',
          'rec_view': 'UI_SETP_REC_VIEW'}
SHUTTER = {0: 'MS', 1: 'ES', 2: 'MS+ES', 3: 'EF'}


def pagesz(n):
    return (n + 0xFFF) & ~0xFFF


def make_mu():
    mu = Uc(UC_ARCH_ARM64, UC_MODE_LITTLE_ENDIAN)
    mu.mem_map(b0.base, pagesz(len(b0.data)))
    mu.mem_write(b0.base, b0.data)
    mu.mem_map(b1.base, pagesz(len(b1.data)))
    mu.mem_write(b1.base, b1.data)
    mu.mem_map(0x10000000, 0x10000)
    mu.reg_write(UC_ARM64_REG_SP, 0x10008000)
    return mu


def eval_flag(fieldA, shutter_type, fieldB, drive):
    mu = make_mu()
    for reg, val in ((UC_ARM64_REG_X0, fieldA), (UC_ARM64_REG_X1, shutter_type),
                     (UC_ARM64_REG_X2, fieldB), (UC_ARM64_REG_X3, 0),
                     (UC_ARM64_REG_X4, drive), (UC_ARM64_REG_X5, 0)):
        mu.reg_write(reg, val)
    mu.reg_write(UC_ARM64_REG_LR, 0x10000000)
    mu.emu_start(0x30308A0, 0x10000000, count=300)
    return mu.reg_read(UC_ARM64_REG_X0) & 0xFFFFFFFF


def natural_key(s):
    import re
    return [int(p) if p.isdigit() else p.lower() for p in re.split(r'(\d+)', s)]


rows = []
for d in sorted(SERIES.iterdir(), key=lambda p: natural_key(p.name)):
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
    v = {k: (s.get(name)['value'] if s.get(name) else None) for k, name in FIELDS.items()}
    sp = v['speed_output'] or 0
    fieldB = sp // 10000
    st = v['shutter_actual']
    ch = (v['drive_ch'] == 21)
    cont = (v['rec_view'] == 2)
    fieldA = 1 if (ch and cont) else 0
    drive = 4 if ch else 0
    flag = eval_flag(fieldA, st, fieldB, drive)
    defect_backup = (ch and st == 1 and sp >= 800000 and cont)
    # предсказание для 08-11
    pkey = None
    for key in pred['owner_test_predictions']:
        if d.name.startswith(key.split('_')[0] + '_') or d.name == key:
            pkey = key
            break
    predicted = pred['owner_test_predictions'].get(pkey, {}).get('flag_prediction') if pkey else None
    rows.append({'label': d.name, 'menu': SHUTTER.get(v['shutter_menu'], v['shutter_menu']),
                 'actual': SHUTTER.get(st, st), 'st_in': st, 'CH': ch, 'CONT': cont,
                 'speed': f'1/{sp // 100}' if sp % 100 == 0 else f'1/{sp / 100:g}',
                 'spdM': v['speed_m_index'], 'fieldB': fieldB, 'fieldA': fieldA,
                 'flag_vm': flag, 'defect_backup_K2': defect_backup,
                 'predicted': predicted,
                 'match_prediction': (flag == predicted) if predicted is not None else None})

result = {'rows': rows,
          'present_threshold_snapshots': [r['label'] for r in rows if r['label'][:2] in ('08', '09', '10', '11')],
          'missing': [k for k in ('09_1-640', '10_1-1000', '11_1-4000')
                      if not any(r['label'].startswith(k.split('_')[0] + '_') for r in rows)]}
(HERE / '4круг_сравнение.json').write_text(json.dumps(result, ensure_ascii=False, indent=2) + '\n', encoding='utf-8')
print('label | menu | actual | CH | CONT | speed | spdM | fieldB | fieldA | flag_VM | defectK2 | predicted | match')
for r in rows:
    print(' | '.join(str(x) for x in [r['label'], r['menu'], r['actual'], r['CH'], r['CONT'], r['speed'],
                                      r['spdM'], r['fieldB'], r['fieldA'], r['flag_vm'], r['defect_backup_K2'],
                                      r['predicted'], r['match_prediction']]))
print('\nпороговые снимки в наличии:', result['present_threshold_snapshots'])
print('отсутствуют:', result['missing'])
