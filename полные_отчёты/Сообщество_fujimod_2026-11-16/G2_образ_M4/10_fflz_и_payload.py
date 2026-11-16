"""10: (а) поиск FFLZ-заголовков на ЛЮБОМ 4-байтном выравнивании (numpy-префильтр);
(б) разбор скрытого payload 0x2300000..0x2470000 внутри «слота» блока 2
    (высокая энтропия 7.7, 1.4 МиБ) — что это: сжатый образ, подпись, таблица?

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
out = {}

# ---------------------------------------------------------- (а) все FFLZ на любом выравнивании
print('== поиск FFLZ-заголовков на любом 4-байтном выравнивании')
n = len(dec) & ~3
w = np.frombuffer(bytes(dec[:n]), dtype='<u4')
idx = np.nonzero((w[3:-1] == 0x4000) & (w[4:] == 4) &
                 (w[:-4] > 0x10000) & (w[:-4] < 0x10000000) &
                 (w[1:-3] > 0x1000) & (w[1:-3] <= w[:-4]))[0]
print(f'  кандидатов-заголовков: {len(idx)}')
found = []
for i in idx:
    off = int(i) * 4
    usize, csize, pages, page_size, align = struct.unpack_from('<5I', dec, off)
    try:
        blk = m4lib.unpack_fflz(dec, off)
    except Exception as e:
        continue
    found.append({'off': off, 'usize': usize, 'csize': csize, 'pages': pages,
                  'dec_sha256': __import__('hashlib').sha256(blk).hexdigest()})
    print(f"  FFLZ @ {off:#x}: usize={usize:#x} csize={csize:#x} pages={pages} "
          f"sha={found[-1]['dec_sha256'][:16]}")
out['fflz_all_align'] = found

# ---------------------------------------------------------- (б) payload 0x2300000..0x2470000
print('\n== payload 0x1690dab..0x24a0274 (щель слота блока 2)')
s, e = 0x1690dab, 0x24a0274
chunk = dec[s:e]
nz = np.nonzero(np.frombuffer(bytes(chunk), dtype=np.uint8) != 0)[0]
print(f'  ненулевых байт: {len(nz)} из {len(chunk)}')
if len(nz):
    print(f'  первый ненулевой: {s + int(nz[0]):#x}, последний: {s + int(nz[-1]):#x}')
    a, b = s + int(nz[0]), s + int(nz[-1]) + 1
    print(f'  диапазон данных: {a:#x}..{b:#x} = {b - a:#x} байт')
    # разбить на блоки по 64 КиБ и показать заполнение
    for off in range(a & ~0xFFFF, b, 0x10000):
        seg = dec[off:off + 0x10000]
        z = seg.count(0) / len(seg)
        ff = seg.count(0xFF) / len(seg)
        print(f'   {off:#010x} zeros={z:.2f} ff={ff:.2f} H={m4lib.entropy(dec, off, min(0x1000, len(seg)))}')
    for off, tag in ((a, 'начало данных'), (0x2300dab, 'высокая энтропия')):
        print(f'  --- {tag} @ {off:#x}')
        for i in range(0, 0x40, 16):
            ch = dec[off + i:off + i + 16]
            print(f'   {off + i:08x}  {ch.hex(" "):<47}  ' +
                  ''.join(chr(c) if 32 <= c < 127 else '.' for c in ch))
    # сигнатуры внутри
    for sig, name in ((b'\x1f\x8b\x08', 'gzip'), (b'\xfd7zXZ', 'xz'), (b'\x28\xb5\x2f\xfd', 'zstd'),
                      (b'\x04\x22\x4d\x18', 'lz4'), (b'hsqs', 'squashfs'), (b'\x7fELF', 'elf'),
                      (b'\xd0\x0d\xfe\xed', 'dtb'), (b'BZh', 'bzip2')):
        hits, pos = [], 0
        while True:
            i = dec.find(sig, pos, e)
            if i < 0 or len(hits) >= 10:
                break
            if i >= s:
                hits.append(i)
            pos = i + 1
        if hits:
            print(f'   {name}: {[hex(x) for x in hits[:6]]}')
    out['payload'] = {'start': hex(a), 'end': hex(b), 'len': b - a}

(HERE / 'fflz_и_payload.json').write_text(json.dumps(out, ensure_ascii=False, indent=1), encoding='utf8')
print('saved fflz_и_payload.json')
