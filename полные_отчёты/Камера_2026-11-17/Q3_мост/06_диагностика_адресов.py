# -*- coding: utf-8 -*-
"""Q3 диагностика адресации: заголовки, слова по смещениям, memcpy-якорь."""
import struct
import sys
from pathlib import Path

HERE = Path(__file__).resolve().parent
sys.path.insert(0, str(HERE))
from q3common import prefix, load, dis  # noqa: E402

p = prefix()
b0 = load('X-H2', 'old', 0)
b2 = load('X-H2', 'old', 2)

def words(b, va, n=8):
    o = b.off(va)
    return ' '.join(f'{struct.unpack_from("<I", b.data, o + 4 * i)[0]:08x}' for i in range(n))

print('prefix[0:0x40]:', p.data[:0x40].hex())
print('prefix words @0x5460C:', words(p, 0x5460C))
print('prefix words @0x4A458:', words(p, 0x4A458))
print('prefix words @0x0:', words(p, 0))
print('prefix words @0x40000:', words(p, 0x40000))
print()
print('block0 header[0:0x40]:', b0.data[:0x40].hex())
print('block2 header[0:0x40]:', b2.data[:0x40].hex())
print('block2 words @0x5460C:', words(b2, 0x5460C))
print()
print('=== block0 memcpy-якорь 0x153CE8C ===')
print(dis(b0, 0x153CE8C, 20))
print()
# плотность прологов stp x29,x30,[sp,#-N]! по префиксу, шаг 0x10000
print('=== префикс: плотность ARM64-прологов по 0x10000 ===')
for o in range(0, len(p.data) - 3, 0x10000):
    cnt = 0
    for k in range(o, min(o + 0x10000, len(p.data) - 3), 4):
        w = struct.unpack_from('<I', p.data, k)[0]
        if (w & 0xffc07fff) == 0xa9807bfd:
            cnt += 1
    print(f'  {o:#08x}: {cnt}')
