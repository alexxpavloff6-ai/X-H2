"""07: что такое префикс DAT 0..0x300274 (загрузчик?) и где вообще упомянуты адреса
companion-SRAM (0xFA2xxxxx), mailbox (0xFF90E100) и reset-handshake (0xFF91C000).

Считает ARM64-идиомы (ret/stp/nop) по окнам, ищет ADRP на страницы 0xFA200000/0xFF900000
и 32/64-битные значения-указатели в префиксе, блоках 0-3 и сыром хвосте. Только чтение.
"""
import json
import struct
import sys
from pathlib import Path

HERE = Path(__file__).resolve().parent
sys.path.insert(0, str(HERE))
import m4lib

fw = m4lib.load_dat(m4lib.DAT_NEW)
dec = fw['dec']
blocks = m4lib.find_fflz(dec)
regions = m4lib.regions(len(dec), blocks)
out = {}

# ---------------------------------------------------------------- 1. префикс: ARM64?
import numpy as np

def arm64_profile(buf, off, length):
    a = np.frombuffer(bytes(buf[off:off + (length & ~3)]), dtype='<u4')
    n = len(a)
    return {'words': n,
            'ret_pct': round(100 * int(np.count_nonzero(a == 0xd65f03c0)) / n, 3),
            'stp_lr_pct': round(100 * int(np.count_nonzero(a == 0xa9bf7bfd)) / n, 3),
            'nop_pct': round(100 * int(np.count_nonzero(a == 0xd503201f)) / n, 3),
            'adrp_pct': round(100 * int(np.count_nonzero((a & 0x9f000000) == 0x90000000)) / n, 3)}


print('== ARM64-идиомы по окнам 256 КиБ (префикс) и в блоках')
pref = []
for off in range(0, 0x300274 - 0x40000, 0x40000):
    p = arm64_profile(dec, off, 0x40000)
    p['off'] = off
    pref.append(p)
for p in pref:
    print(f"  prefix {p['off']:#08x}: ret={p['ret_pct']:5.2f}% stp_lr={p['stp_lr_pct']:5.2f}% "
          f"nop={p['nop_pct']:4.2f}% adrp={p['adrp_pct']:4.2f}%")
out['prefix_arm64'] = pref
for idx in (0, 1, 2, 3):
    b = m4lib.load_block('X-H2', 'new', idx)
    p = arm64_profile(b.data, 0, len(b.data))
    p['block'] = idx
    print(f"  block{idx}: ret={p['ret_pct']:5.2f}% stp_lr={p['stp_lr_pct']:5.2f}% "
          f"nop={p['nop_pct']:4.2f}% adrp={p['adrp_pct']:4.2f}%")
    out.setdefault('blocks_arm64', []).append(p)

# ---------------------------------------------------------------- 2. ссылки на адреса
TARGETS = {
    'companion_sram_FA200000': (0xFA200000, 0xFFF00000),
    'companion_sram_FA210000': (0xFA210000, 0xFFFFF000),
    'companion_sram_top_FA300000': (0xFA300000, 0xFFFFF000),
    'mailbox_FF90E100': (0xFF90E100, 0xFFFFFFFF),
    'reset_handshake_FF91C000': (0xFF91C000, 0xFFF00000),
    'reset_handshake_FF91C00C': (0xFF91C00C, 0xFFFFFFFF),
    'flash_aperture_F0000000': (0xF0000000, 0xF0000000),
}


def find_words(buf, value, mask, start=0, end=None, limit=200):
    import array
    end = len(buf) if end is None else end
    n = (end - start) // 4 * 4
    a = array.array('I')
    a.frombytes(bytes(buf[start:start + n]))
    res = []
    for i, w in enumerate(a):
        if (w & mask) == (value & mask):
            res.append(start + 4 * i)
            if len(res) >= limit:
                break
    return res


def find_qwords(buf, value, start=0, end=None, limit=200):
    end = len(buf) if end is None else end
    res, pos = [], start
    pat = struct.pack('<Q', value)
    pat4 = struct.pack('<I', value)
    while True:
        i = buf.find(pat, pos, end)
        j = buf.find(pat4, pos, end)
        if i < 0 and j < 0:
            return res
        k = min(x for x in (i, j) if x >= 0)
        res.append(k)
        if len(res) >= limit:
            return res
        pos = k + 1


print('\n== ссылки на адреса companion/mailbox/reset по областям')
refs = {}
for name, (val, mask) in TARGETS.items():
    rows = []
    for s, e, rname in regions:
        if rname == 'ecdsa_signature':
            continue
        hits = find_words(dec, val, mask, s, e) if mask != 0xFFFFFFFF else find_qwords(dec, val, s, e)
        if hits:
            rows.append({'region': f'{rname}@{s:#x}', 'count': len(hits),
                         'sample': [hex(h) for h in hits[:10]]})
    for idx in (0, 1, 2, 3):
        b = m4lib.load_block('X-H2', 'new', idx)
        hits = find_words(b.data, val, mask) if mask != 0xFFFFFFFF else find_qwords(b.data, val)
        if hits:
            rows.append({'region': f'block{idx}', 'count': len(hits),
                         'sample': [hex(b.base + h) for h in hits[:10]]})
    refs[name] = rows
    print(f'  {name}:')
    for r in rows:
        print(f"    {r['region']:22s} n={r['count']:4d} {r['sample'][:6]}")
    if not rows:
        print('    нет вхождений')
out['address_refs'] = refs

# ---------------------------------------------------------------- 3. ADRP на страницы
sys.path.insert(0, str(m4lib.ANALYSIS / 'Сравнение_версий_2026-11-16'))
import fwcommon

print('\n== ADRP-сайты на страницы 0xFA200000 / 0xFA000000 / 0xFF900000 / 0xFF91C000')
adrp = {}
for idx in (0, 1, 2):
    b = fwcommon.load('X-H2', 'new', idx)
    for page in (0xFA200000, 0xFA000000, 0xFF900000, 0xFF91C000, 0xFF800000):
        sites = fwcommon.adrp_sites(b, page)
        if sites:
            adrp[f'block{idx}@{page:#x}'] = [(hex(s), r) for s, r in sites[:20]]
            print(f'  block{idx} page {page:#x}: {len(sites)} сайтов {[hex(s) for s, _ in sites[:6]]}')
out['adrp'] = adrp

(HERE / 'адреса_и_префикс.json').write_text(json.dumps(out, ensure_ascii=False, indent=1), encoding='utf8')
print('saved адреса_и_префикс.json')
