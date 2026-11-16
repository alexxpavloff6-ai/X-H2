"""13: итоговые измерения (исправленная метрика BL) + опровержение кандидатов + самопроверка.

* BL теперь считается для обоих вариантов J1: (hi & 0xD0) == 0xD0.
* Для топ-кандидатов «таблиц векторов» считается гистограмма разностей соседних слов:
  постоянный/периодический шаг означает таблицу данных, а не таблицу векторов.
* Самопроверка: в случайный буфер кладётся синтетический образ ARMv7-M (SP + 16 векторов
  с размахом > 0x1000 + Thumb-код с правильными BL/BX LR) и проверяется, что детекторы
  его находят. Только чтение DAT.
"""
import json
import random
import struct
import sys
from collections import Counter
from pathlib import Path

import numpy as np

HERE = Path(__file__).resolve().parent
sys.path.insert(0, str(HERE))
import m4lib

fw = m4lib.load_dat(m4lib.DAT_NEW)
dec = fw['dec']
blocks = [m4lib.load_block('X-H2', 'new', i) for i in range(4)]
blocks_all = m4lib.find_fflz(dec)
out = {'metrics': {}, 'diff_hist': {}, 'selftest': {}}

print('== итоговые Thumb-метрики (исправленный BL), окна 64 КиБ')
for s, e, rname in m4lib.regions(len(dec), blocks_all):
    if rname == 'ecdsa_signature' or e - s < 0x10000:
        continue
    rows = m4lib.windowed_thumb_np(dec, 0x10000, s, e)
    hw = sum(r['halfwords'] for r in rows)
    bl = sum(r['bl'] for r in rows)
    bx = sum(r['bx_lr'] for r in rows)
    push = sum(r['push_lr'] for r in rows)
    out['metrics'][f'{rname}@{s:#x}'] = {'halfwords': hw, 'bl': bl, 'bx_lr': bx,
                                         'push_lr': push,
                                         'bl_pct': round(100 * bl / hw, 4),
                                         'bx_lr_pct': round(100 * bx / hw, 4),
                                         'push_pct': round(100 * push / hw, 4)}
    print(f"  {rname:9s} {s:#010x}..{e:#010x}: полуслов={hw} bl={bl} ({100 * bl / hw:.4f}%) "
          f"bx_lr={bx} ({100 * bx / hw:.4f}%) push_lr={push} ({100 * push / hw:.3f}%)")
for i, b in enumerate(blocks):
    m = m4lib.thumb_metrics_np(b.data, 0, len(b.data))
    out['metrics'][f'block{i}'] = m
    print(f"  block{i} len={len(b.data):#x}: bl={m['bl']} ({m['bl_pct']}%) "
          f"bx_lr={m['bx_lr']} ({m['bx_lr_pct']}%) push_lr={m['push_lr_pct']}%")

print('\n== опровержение топ-кандидатов «таблиц векторов»: гистограмма разностей')
CANDS = [
    ('block0', 0x1ACBDFC, 176), ('block0', 0x17456E8, 158), ('raw_tail', 0x3B80538, 112),
    ('raw_tail', 0x2978944, 76), ('block1', 0x37D4078, 97), ('raw', 0x1AE04, 200),
    ('block0', 0x1745A74, 200), ('block0', 0x1748668, 111),
]


def get_buf(name):
    if name == 'block0':
        return blocks[0].data, blocks[0].base
    if name == 'block1':
        return blocks[1].data, blocks[1].base
    if name == 'raw':
        return dec[:0x300274], 0
    if name == 'raw_tail':
        return dec[0x284375c:], 0x284375c
    raise KeyError(name)


for name, va, nvec in CANDS:
    buf, base = get_buf(name)
    i = va - base
    vals = list(struct.unpack_from(f'<{nvec}I', buf, i + 4))
    diffs = [vals[k + 1] - vals[k] for k in range(len(vals) - 1)]
    c = Counter(diffs).most_common(4)
    sp = struct.unpack_from('<I', buf, i)[0]
    print(f'  {name} @ {va:#x}: SP={sp:#x}, первые {[hex(v) for v in vals[:5]]}, '
          f'разности (топ): {[(hex(d) if d >= 0 else "-" + hex(-d), n) for d, n in c]}')
    out['diff_hist'][f'{name}@{va:#x}'] = {'sp': hex(sp), 'top_diffs': [[str(d), n] for d, n in c],
                                           'first': [hex(v) for v in vals[:8]]}

print('\n== самопроверка детекторов на посаженном образе ARMv7-M')
random.seed(1234)
ok_vec = ok_thumb = 0
for trial in range(20):
    size = 0x40000
    buf = bytearray(random.getrandbits(8) for _ in range(0x4000)) * (size // 0x4000)
    # смещение не выровнено на страницу — детектор должен найти по 4-байтному выравниванию
    pos = random.randrange(0, size - 0x8000) & ~3
    sp = random.choice([0xFA210000, 0xFA240000, 0x20008000, 0x10000])
    base_code = random.choice([0x1001, 0x8001, 0xFA21001])
    vecs = [sp] + [base_code + 0x400 * k for k in range(15)]
    buf[pos:pos + 4 * len(vecs)] = b''.join(struct.pack('<I', v) for v in vecs)
    # Thumb-«код» с корректными push/bl/bx lr
    code = bytearray()
    for k in range(0x800):
        pat = [0xB510, 0xF000, 0xF800, 0x4804, 0x4770]
        code += struct.pack('<H', pat[k % 5])
    buf[pos + 0x2000:pos + 0x2000 + len(code)] = code
    import array
    a = array.array('I')
    a.frombytes(bytes(buf[:len(buf) & ~3]))
    cands = m4lib.vector_candidates(a, 0, min_vec=8, cluster=0x100000)
    hit_v = any(c['off'] <= pos < c['off'] + 4 * (c['nvec'] + 1) for c in cands) or \
            any(abs(c['off'] - pos) < 0x10 for c in cands)
    m = m4lib.thumb_metrics_np(bytes(buf), pos + 0x2000, len(code))
    hit_t = m['bl_pct'] > 1 and m['bx_lr_pct'] > 1
    ok_vec += bool(hit_v)
    ok_thumb += bool(hit_t)
    if trial < 3:
        print(f"  проба {trial}: SP={sp:#x} base={base_code:#x} pos={pos:#x} -> "
              f"векторы={'найдено' if hit_v else 'ПРОПУЩЕНО'}, "
              f"Thumb bl={m['bl_pct']}% bx_lr={m['bx_lr_pct']}% -> {'найдено' if hit_t else 'ПРОПУЩЕНО'}")
print(f'  итог: векторы найдены в {ok_vec}/20, Thumb-код в {ok_thumb}/20')
out['selftest'] = {'vector_hits': ok_vec, 'vector_trials': 20,
                   'thumb_hits': ok_thumb, 'thumb_trials': 20}

(HERE / 'итоговые_измерения.json').write_text(json.dumps(out, ensure_ascii=False, indent=1), encoding='utf8')
print('saved итоговые_измерения.json')
