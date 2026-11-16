"""04: плотность «идиом ARMv7-M» (Thumb) по всему DAT 5.33 и по распакованным блокам.

Метрики m4lib.thumb_metrics (push {..,lr} = 0xB5xx, bx lr = 0x4770, BL, ldr [pc,#imm])
считаются по окнам 64 КиБ. Случайные данные дают ~0.4 % push_lr; реальный код — проценты.
Печатает окна-лидеры и сохраняет `thumb_метрики.json`. Только чтение.
"""
import json
import sys
from pathlib import Path

HERE = Path(__file__).resolve().parent
sys.path.insert(0, str(HERE))
import m4lib

fw = m4lib.load_dat(m4lib.DAT_NEW)
dec = fw['dec']
n = len(dec)
blocks = m4lib.find_fflz(dec)
regions = m4lib.regions(n, blocks)
out = {'dat': fw['path'], 'regions': [], 'blocks': []}


def summarise(name, buf, start=0, end=None):
    rows = m4lib.windowed_thumb(buf, 0x10000, start, end)
    good = sorted(rows, key=lambda r: -r['code_score'])[:15]
    print(f'{name}: окон={len(rows)} максимум code_score={good[0]["code_score"] if good else 0}')
    for r in good[:10]:
        print(f"   {r['off']:#010x} score={r['code_score']:6.2f} push_lr={r['push_lr_pct']:5.2f}% "
              f"bx_lr={r['bx_lr_pct']:5.2f}% bl={r['bl_pct']:5.2f}% ldr_pc={r['ldr_pc_pct']:5.2f}% "
              f"udf={r['udf_pct']:4.1f}%")
    return rows, good


for s, e, rname in regions:
    rows, good = summarise(f'raw {rname} {s:#x}..{e:#x}', dec, s, e)
    out['regions'].append({'name': rname, 'start': s, 'end': e, 'top': good,
                           'median_score': rows[len(rows) // 2]['code_score'] if rows else 0})

for idx in (0, 1, 2, 3):
    b = m4lib.load_block('X-H2', 'new', idx)
    rows, good = summarise(f'block{idx} base={b.base:#x} len={len(b.data):#x}', b.data)
    out['blocks'].append({'idx': idx, 'base': b.base, 'len': len(b.data), 'top': good,
                          'median_score': rows[len(rows) // 2]['code_score'] if rows else 0})

(HERE / 'thumb_метрики.json').write_text(json.dumps(out, ensure_ascii=False, indent=1), encoding='utf8')
print('saved thumb_метрики.json')
