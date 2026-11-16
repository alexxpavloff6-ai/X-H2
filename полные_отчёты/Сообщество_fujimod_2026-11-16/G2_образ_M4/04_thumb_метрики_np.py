"""04: «идиомы ARMv7-M» по всему DAT и блокам — numpy-версия, окна 16 КиБ.

Решающий признак настоящего Thumb-кода: присутствие `bl` (0xF0..,0xD0..) и `bx lr`
(0x4770) — в скомпилированном коде M4 их всегда сотни на 64 КиБ. В данных обе
величины близки к нулю, даже если частота байта 0xB5 (push) случайно высока.

Печатает глобальные максимумы и сохраняет `thumb_метрики_np.json`. Только чтение.
"""
import json
import sys
from pathlib import Path

HERE = Path(__file__).resolve().parent
sys.path.insert(0, str(HERE))
import m4lib

WIN = 0x4000
fw = m4lib.load_dat(m4lib.DAT_NEW)
dec = fw['dec']
blocks = m4lib.find_fflz(dec)
regions = m4lib.regions(len(dec), blocks)
out = {'dat': fw['path'], 'win': WIN, 'regions': [], 'blocks': []}


def run(name, buf, start=0, end=None, tag='region'):
    rows = m4lib.windowed_thumb_np(buf, WIN, start, end)
    top = sorted(rows, key=lambda r: -r['code_score'])[:12]
    best_push = max(rows, key=lambda r: r['push_lr']) if rows else None
    tot_bl = sum(r['bl'] for r in rows)
    tot_bx = sum(r['bx_lr'] for r in rows)
    tot_hw = sum(r['halfwords'] for r in rows)
    print(f'{name}: окон={len(rows)} всего bl={tot_bl} bx_lr={tot_bx} '
          f'({100 * (tot_bl + tot_bx) / max(tot_hw, 1):.3f}% полуслов)')
    for r in top[:8]:
        print(f"   {r['off']:#010x} score={r['code_score']:6.2f} push={r['push_lr_pct']:5.2f}% "
              f"bx_lr={r['bx_lr']:4d} bl={r['bl']:4d} ldr_pc={r['ldr_pc_pct']:5.2f}%")
    if best_push:
        print(f"   max push_lr {best_push['push_lr_pct']:.2f}% @ {best_push['off']:#x} "
              f"(bl={best_push['bl']}, bx_lr={best_push['bx_lr']})")
    rec = {'name': name, 'windows': len(rows), 'total_bl': tot_bl, 'total_bx_lr': tot_bx,
           'total_halfwords': tot_hw, 'top': top, 'max_push': best_push}
    out['regions' if tag == 'region' else 'blocks'].append(rec)
    return rec


for s, e, rname in regions:
    if rname == 'ecdsa_signature':
        continue
    run(f'raw {rname} {s:#x}..{e:#x}', dec, s, e)

for idx in (0, 1, 2, 3):
    b = m4lib.load_block('X-H2', 'new', idx)
    run(f'block{idx} base={b.base:#x} len={len(b.data):#x}', b.data, tag='block')

(HERE / 'thumb_метрики_np.json').write_text(json.dumps(out, ensure_ascii=False, indent=1), encoding='utf8')
print('saved thumb_метрики_np.json')
