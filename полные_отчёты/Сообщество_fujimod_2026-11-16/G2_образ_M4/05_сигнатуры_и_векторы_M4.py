"""05: (а) сигнатуры контейнеров/ФС по всему DAT в обоих представлениях;
(б) целевой поиск таблицы векторов «в системе координат M4» (адрес 0 = 0xFA200000).

По карте fujimod `catalog/soc/xp5/soc.json` ядро core4 (Cortex-M4) видит адрес 0 как
физический 0xFA200000 (companion-SRAM), а `hardware.companion.vector_base = 0`.
Значит, если образ M4 лежит в DAT, его SP и векторы — малые адреса 0..0x100000,
а не 0xFA2xxxxx. Только чтение.
"""
import json
import re
import sys
from pathlib import Path

HERE = Path(__file__).resolve().parent
sys.path.insert(0, str(HERE))
import m4lib

SIGS = {
    'ELF': b'\x7fELF', 'gzip': b'\x1f\x8b\x08', 'dtb': b'\xd0\x0d\xfe\xed',
    'xz': b'\xfd7zXZ', 'zstd': b'\x28\xb5\x2f\xfd', 'lz4': b'\x04\x22\x4d\x18',
    'squashfs': b'hsqs', 'cramfs': b'\x45\x3d\xcd\x28', 'erofs': b'\xe2\xe1\xf5\xe0',
    'ubi': b'UBI#', 'jffs2': b'\x85\x19', 'cpio': b'070701', 'tar': b'ustar',
    'png': b'\x89PNG', 'jpeg': b'\xff\xd8\xff', 'bz2': b'BZh', 'zlib78': b'\x78\x9c',
    'zlib78da': b'\x78\xda', 'zlib7801': b'\x78\x01',
}

fw = m4lib.load_dat(m4lib.DAT_NEW)
raw, dec = fw['raw'], fw['dec']
out = {'signatures': {}, 'companion_vectors': []}
print('== сигнатуры (ищем и в dec, и в raw; первые 8 вхождений каждого типа)')
for name, sig in SIGS.items():
    for label, buf in (('dec', dec), ('raw', raw)):
        hits, pos = [], 0
        while True:
            i = buf.find(sig, pos)
            if i < 0 or len(hits) >= 200:
                break
            hits.append(i)
            pos = i + 1
        if hits:
            print(f"  {name:9s} {label}: {len(hits)} вхождений, первые {[hex(x) for x in hits[:8]]}")
            out['signatures'][f'{name}_{label}'] = [hex(x) for x in hits[:200]]

# ---------------------------------------------------------- целевой поиск векторов M4
print('\n== векторы в системе координат M4 (адрес 0 = companion-SRAM 0xFA200000)')
LOW = 0x100000          # 1 МиБ companion-SRAM


def companion_candidates(buf, base_va, name):
    """SP внутри 0..1 МиБ и >=8 подряд нечётных слов в 0..1 МиБ, размах >= 0x2000."""
    import array
    a = array.array('I')
    a.frombytes(bytes(buf[:len(buf) & ~3]))
    if sys.byteorder != 'little':
        a.byteswap()
    res = []
    n = len(a)
    i = 0
    while i < n - 10:
        w0 = a[i]
        if w0 < 0x1000 or w0 > LOW or (w0 & 3):
            i += 1
            continue
        vals, j = [], i + 1
        while j < n and (a[j] & 1) and a[j] < LOW:
            vals.append(a[j])
            j += 1
            if len(vals) >= 128:
                break
        if len(vals) >= 8:
            span = max(vals) - min(vals)
            if span >= 0x2000:
                res.append({'off': base_va + 4 * i, 'sp': w0, 'nvec': len(vals),
                            'min': min(vals), 'max': max(vals), 'span': span,
                            'vecs': vals[:16]})
                i = j
                continue
        i += 1
    res.sort(key=lambda r: -r['nvec'])
    print(f'  {name}: кандидатов {len(res)}')
    for r in res[:10]:
        print(f"    off={r['off']:#x} SP={r['sp']:#x} nvec={r['nvec']} "
              f"код={r['min']:#x}..{r['max']:#x} span={r['span']:#x} "
              f"vecs={[hex(v) for v in r['vecs'][:8]]}")
    return res[:20]


blocks = m4lib.find_fflz(dec)
for s, e, rname in m4lib.regions(len(dec), blocks):
    if rname == 'ecdsa_signature' or e - s < 0x4000:
        continue
    out['companion_vectors'] += [dict(r, buf=rname) for r in companion_candidates(dec[s:e], s, f'{rname} {s:#x}')]

for idx in (0, 1, 2, 3):
    b = m4lib.load_block('X-H2', 'new', idx)
    out['companion_vectors'] += [dict(r, buf=f'block{idx}') for r in
                                 companion_candidates(b.data, b.base, f'block{idx} base={b.base:#x}')]

(HERE / 'сигнатуры_и_векторы_M4.json').write_text(json.dumps(out, ensure_ascii=False, indent=1), encoding='utf8')
print('saved сигнатуры_и_векторы_M4.json')
