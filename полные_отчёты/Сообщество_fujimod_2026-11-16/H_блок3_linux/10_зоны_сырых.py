"""Карта заполненных зон в сырых областях DAT + первые байты каждой зоны.

Ищет страницы, не заполненные целиком 0x00/0xFF, группирует их в зоны.
Только чтение DAT.
"""
from pathlib import Path
import math
import struct
from collections import Counter

HERE = Path(__file__).resolve().parent
DAT_NEW = Path(r'<корень проекта>\FIRMWARE\ver new\FWUP0028 (2).DAT')
TRANS = bytes.maketrans(bytes(range(256)), bytes(255 - i for i in range(256)))
OUT = HERE / 'DAT_зоны.txt'
PAGE = 0x1000

REGIONS = [
    (0x0, 0x300274, 'заголовок DAT'),
    (0x1690dab, 0x24a0274, 'между бл.2 и бл.3'),
    (0x284375c, 0x3cb0274, 'бл.3 -> Image'),
    (0x56f0274, 0x6931508, 'хвост после ядра'),
]


def entropy(b):
    if not b:
        return 0.0
    c = Counter(b)
    n = len(b)
    return -sum(v / n * math.log2(v / n) for v in c.values())


def printable(b, span=64):
    return ''.join(chr(c) if 32 <= c < 127 else '.' for c in b[:span])


def main():
    dec = DAT_NEW.read_bytes().translate(TRANS)
    out = []
    for a, z, nm in REGIONS:
        out.append(f'===== 0x{a:x}..0x{z:x} ({nm}) =====')
        zones = []
        cur = None
        for p in range(a, z, PAGE):
            page = dec[p:min(p + PAGE, z)]
            blank = all(c in (0, 0xff) for c in page)
            if not blank and cur is None:
                cur = p
            elif blank and cur is not None:
                zones.append((cur, p))
                cur = None
        if cur is not None:
            zones.append((cur, z))
        out.append(f'  заполненных зон: {len(zones)}')
        for s, e in zones:
            seg = dec[s:e]
            out.append(f'  --- 0x{s:x}..0x{e:x} len=0x{e-s:x} H={entropy(seg[:0x2000]):.2f} '
                       f'перв16={seg[:16].hex(" ")} | {printable(seg, 40)}')
        out.append('')
    OUT.write_text('\n'.join(out) + '\n', encoding='utf-8')
    print('written', OUT)


if __name__ == '__main__':
    main()
