"""21: финальные проверки для отчёта.

(а) статистика векторной таблицы образа M4 (сколько записей, сколько IRQ, какие обработчики);
(б) есть ли в блоках A53 (0-2) таблицы с адресами mailbox 0xFF90E1xx — канал A53↔M4;
(в) дамп таблицы MOVDC-дескрипторов в блоке 1 (0xFF970000/0xFF971000/...);
(г) счётчик и карта «страниц периферии» в образе M4.

Только чтение.
"""
import json
import re
import struct
import sys
from collections import Counter
from pathlib import Path

import numpy as np

HERE = Path(__file__).resolve().parent
sys.path.insert(0, str(HERE))
import m4lib

IMG_OFF, IMG_LEN = 0x1C0274, 0x31A80
fw = m4lib.load_dat(m4lib.DAT_NEW)
dec = fw['dec']
img = dec[IMG_OFF:IMG_OFF + IMG_LEN]
blocks = [m4lib.load_block('X-H2', 'new', i) for i in range(4)]
out = {}

print('== (а) векторная таблица образа M4')
vec = list(struct.unpack_from('<512I', img, 0))
nz = [(i, v) for i, v in enumerate(vec) if v]
print(f'  всего записей: 512, ненулевых: {len(nz)}')
irq = [(i, v) for i, v in nz if i >= 16]
print(f'  IRQ-векторов ненулевых: {len(irq)} (из {512 - 16})')
handlers = Counter(v for _, v in nz)
print('  обработчики:', [(hex(h), c) for h, c in handlers.most_common(12)])
print('  первые системные:', [(i, hex(v)) for i, v in nz if i < 16])
uniq_irq = Counter(v for _, v in irq)
print('  уникальных IRQ-обработчиков:', [(hex(h), c) for h, c in uniq_irq.most_common(8)])
out['vectors'] = {'total': 512, 'nonzero': len(nz), 'irq_nonzero': len(irq),
                  'handlers': {hex(h): c for h, c in handlers.items()},
                  'system': {i: hex(v) for i, v in nz if i < 16}}

print('\n== (б) mailbox-регистры 0xFF90E1xx в таблицах блоков A53')
for i, b in enumerate(blocks[:3]):
    a = np.frombuffer(b.data[:len(b.data) & ~3], dtype='<u4')
    m = np.nonzero((a >= 0xFF90E100) & (a < 0xFF90E140))[0]
    print(f'  block{i}: {len(m)} вхождений ' + (str([hex(b.base + int(x) * 4) for x in m[:10]]) if len(m) else ''))
    if len(m):
        va = b.base + int(m[0]) * 4
        o = b.off(va) - 0x20
        for k in range(0, 0x60, 16):
            ch = b.data[o + k:o + k + 16]
            print(f'    {va - 0x20 + k:09x}  {ch.hex(" ")}  ' +
                  ''.join(chr(c) if 32 <= c < 127 else '.' for c in ch))
    out[f'mailbox_block{i}'] = [hex(b.base + int(x) * 4) for x in m[:20]]

print('\n== (в) таблица MOVDC-дескрипторов в блоке 1 (около VA 0x385e140)')
b1 = blocks[1]
o = b1.off(0x385E140) - 0x20
for k in range(0, 0x120, 16):
    ch = b1.data[o + k:o + k + 16]
    vals = struct.unpack_from('<4I', b1.data, o + k)
    print(f'  {0x385E120 + k:09x}  {ch.hex(" "):<47}  {" ".join(hex(v) for v in vals)}')

print('\n== (г) карта периферийных страниц в образе M4 (по всем 4-байтным словам)')
a = np.frombuffer(img[:len(img) & ~3], dtype='<u4')
pages = Counter()
for v in a:
    if 0x5F900000 <= int(v) < 0x5FA00000:
        pages[int(v) & 0xFFFFF000] += 1
for p, c in sorted(pages.items()):
    print(f'  0x{p:08x}  x{c}')
out['m4_pages'] = {hex(p): c for p, c in pages.items()}

(HERE / 'финальные_проверки.json').write_text(json.dumps(out, ensure_ascii=False, indent=1), encoding='utf8')
print('saved финальные_проверки.json')
