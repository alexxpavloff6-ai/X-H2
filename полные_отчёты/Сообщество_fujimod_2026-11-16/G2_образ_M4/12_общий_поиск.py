"""12: (а) полностью общий поиск таблиц векторов (без предположений о карте SRAM):
        w0 — чётное ненулевое, далее >=10 нечётных слов, размах кода >= 0x1000;
    (б) гистограмма целей ADRP в префиксе и блоках 0-2 (какие периферийные базы реально
        использует прошивка A53);
    (в) самопроверка детекторов на синтетическом образе M4 (таблица векторов + Thumb-код),
        чтобы показать чувствительность метода.

Только чтение.
"""
import json
import struct
import sys
from pathlib import Path

import numpy as np

HERE = Path(__file__).resolve().parent
sys.path.insert(0, str(HERE))
import m4lib

fw = m4lib.load_dat(m4lib.DAT_NEW)
dec = fw['dec']
blocks = [m4lib.load_block('X-H2', 'new', i) for i in range(4)]
out = {}


def generic_vectors(buf, base_va, name, min_vec=10, min_span=0x1000, cluster=0x400000):
    a = np.frombuffer(bytes(buf[:len(buf) & ~3]), dtype='<u4')
    n = len(a)
    odd = (a & 1).astype(np.int8)
    res = []
    i = 0
    while i < n - min_vec - 1:
        if a[i] == 0 or (a[i] & 1) or a[i] == 0xFFFFFFFF:
            i += 1
            continue
        j = i + 1
        while j < n and odd[j] and (int(a[j]) - int(a[i + 1]) < cluster) and \
                (int(a[i + 1]) - int(a[j]) < cluster):
            j += 1
            if j - i > 200:
                break
        vals = a[i + 1:j]
        if len(vals) >= min_vec:
            span = int(vals.max()) - int(vals.min())
            uniq = len(np.unique(vals))
            if span >= min_span and uniq >= min_vec // 2:
                res.append({'off': base_va + 4 * i, 'sp': int(a[i]), 'nvec': len(vals),
                            'span': span, 'uniq': uniq, 'lo': int(vals.min()), 'hi': int(vals.max())})
                i = j
                continue
        i += 1
    res.sort(key=lambda r: -r['nvec'])
    print(f'  {name}: {len(res)} кандидатов (span>={min_span:#x})')
    for r in res[:12]:
        print(f"    off={r['off']:#x} SP={r['sp']:#x} nvec={r['nvec']} uniq={r['uniq']} "
              f"код={r['lo']:#x}..{r['hi']:#x}")
    return res[:30]


print('== (а) общий поиск таблиц векторов по всему DAT (сырые области + блоки)')
allv = {}
blocks_all = m4lib.find_fflz(dec)
for s, e, rname in m4lib.regions(len(dec), blocks_all):
    if rname == 'ecdsa_signature' or e - s < 0x4000:
        continue
    allv[rname] = generic_vectors(dec[s:e], s, f'{rname} {s:#x}')
for i, b in enumerate(blocks):
    allv[f'block{i}'] = generic_vectors(b.data, b.base, f'block{i}')
out['generic_vectors'] = allv

print('\n== (б) гистограмма целей ADRP (топ-15 страниц)')


def adrp_hist(buf, base, name):
    a = np.frombuffer(bytes(buf[:len(buf) & ~3]), dtype='<u4')
    m = (a & 0x9f000000) == 0x90000000
    idx = np.nonzero(m)[0]
    if not len(idx):
        print(f'  {name}: ADRP нет')
        return {}
    immlo = ((a[idx] >> 29) & 3).astype(np.int64)
    immhi = ((a[idx] >> 5) & 0x7ffff).astype(np.int64)
    imm = (immhi << 2) | immlo
    imm = np.where(imm & (1 << 20), imm - (1 << 21), imm)
    pc = base + idx * 4
    page = (pc & ~0xfff) + (imm << 12)
    vals, counts = np.unique(page, return_counts=True)
    order = np.argsort(-counts)
    rows = []
    for k in order[:15]:
        rows.append({'page': hex(int(vals[k])), 'count': int(counts[k])})
        print(f"  {name}: {vals[k]:#012x} — {counts[k]}")
    return {'total_adrp': len(idx), 'top': rows}


hist = {}
hist['prefix'] = adrp_hist(dec[:0x300274], 0, 'prefix')
for i in range(3):
    hist[f'block{i}'] = adrp_hist(blocks[i].data, blocks[i].base, f'block{i}')
out['adrp_hist'] = hist

print('\n== (в) самопроверка: синтетический образ M4')
# таблица векторов: SP = 0xFA210000, 16 векторов в 0x0..0x4000 (взгляд M4), затем код
img = bytearray()
vecs = [0xFA210000] + [0x1001 + 0x400 * k for k in range(15)]
img += b''.join(struct.pack('<I', v) for v in vecs)
img += b'\x00' * (0x100 - len(img))
# «код»: чередование push {r4,lr}=0xB510, bx lr=0x4770, bl=0xF000 0xF800
code = bytearray()
for k in range(0x1000):
    code += struct.pack('<H', [0xB510, 0x4770, 0xF000, 0xF800, 0x4804][k % 5])
img += code
print(f'  синтетический образ: {len(img):#x} байт, SP={vecs[0]:#x}, векторов {len(vecs)}')
found = generic_vectors(bytes(img), 0, 'synthetic')
m = m4lib.thumb_metrics_np(bytes(img), 0x100, 0x1000)
print(f"  Thumb-метрики синтетики: push={m['push_lr_pct']}% bl={m['bl_pct']}% "
      f"bx_lr={m['bx_lr_pct']}% score={m['code_score']}")
out['selftest'] = {'vectors_detected': bool(found), 'first': found[0] if found else None, 'thumb': m}

(HERE / 'общий_поиск.json').write_text(json.dumps(out, ensure_ascii=False, indent=1, default=str),
                                      encoding='utf8')
print('saved общий_поиск.json')
