"""02: профиль «сырых» (не-FFLZ) областей DAT 5.33.

Для каждой области считает по окнам 64 КиБ: энтропию, долю печатных байт, длиннейшую
строку, долю нулевых байт. Ищет сигнатуры ELF/gzip/DTB/FFLZ по всей сырой части с
шагом 0x40 (а не 0x1000). Только чтение.
"""
import json
import math
import struct
import sys
from pathlib import Path

HERE = Path(__file__).resolve().parent
sys.path.insert(0, str(HERE))
import m4lib

fw = m4lib.load(m4lib.DAT_NEW)
dec = fw['dec']
n = len(dec)
blocks = m4lib.find_fflz(dec)
regions = m4lib.regions(n, blocks)
RAW = [(s, e, name) for s, e, name in regions if name.startswith('raw')]
out = {'regions': []}


def window_stats(s, e, win=0x10000):
    rows = []
    for off in range(s, e, win):
        chunk = dec[off:min(off + win, e)]
        if not chunk:
            break
        c = [0] * 256
        for b in chunk:
            c[b] += 1
        ent = 0.0
        for k in c:
            if k:
                p = k / len(chunk)
                ent -= p * math.log2(p)
        pr = sum(c[32:127]) / len(chunk)
        rows.append({'off': off, 'ent': round(ent, 2), 'pr': round(pr, 3),
                     'zero': round(c[0] / len(chunk), 3), 'ff': round(c[255] / len(chunk), 3)})
    return rows


for s, e, name in RAW:
    rows = window_stats(s, e)
    out['regions'].append({'name': name, 'start': s, 'end': e, 'len': e - s, 'windows': rows})
    # сжатая сводка: доля окон разного типа
    txt = [r for r in rows if r['pr'] > 0.3]
    pad = [r for r in rows if r['zero'] > 0.95 or r['ff'] > 0.95]
    high = [r for r in rows if r['ent'] > 7.2]
    print(f"{name} {s:#x}..{e:#x} len={e-s:#x}: окон={len(rows)} текст={len(txt)} "
          f"паддинг={len(pad)} высокая_энтропия={len(high)}")
    # печатаем окна, не являющиеся паддингом (первые/интересные)
    interesting = [r for r in rows if not (r['zero'] > 0.95 or r['ff'] > 0.95)]
    print(f"   не-паддинг окон: {len(interesting)}")
    for r in interesting[:10]:
        print(f"     {r['off']:#x} H={r['ent']} pr={r['pr']} z={r['zero']} ff={r['ff']}")
    if len(interesting) > 10:
        print(f"     ... последнее {interesting[-1]['off']:#x} H={interesting[-1]['ent']}")
    # границы паддинга
    print('   первые 64 байта:', dec[s:s + 64].hex(' '))

# сигнатуры по всей сырой части, шаг 0x40
sigs = {b'\x7fELF': 'ELF', b'\x1f\x8b\x08': 'gzip', b'\xd0\x0d\xfe\xed': 'DTB',
        b'\xfd7zXZ': 'xz', b'\x5d\x00\x00': 'lzma?', b'BZh': 'bzip2'}
hits = {v: [] for v in sigs.values()}
for s, e, name in RAW:
    for off in range(s, e - 4, 0x40):
        for sig, tag in sigs.items():
            if dec[off:off + len(sig)] == sig:
                if len(hits[tag]) < 50:
                    hits[tag].append(hex(off))
print('signatures:', {k: v[:10] for k, v in hits.items()})
out['signatures'] = hits

(HERE / 'профиль_сырых.json').write_text(json.dumps(out, ensure_ascii=False, indent=1), encoding='utf8')
print('saved профиль_сырых.json')
