"""Проба неопознанного payload @0x2300274 (1.5 МБ): сигнатуры, распаковка, текст,
структура — в обычной и инвертированной (XOR 0xFF) полярности.

Только чтение DAT.
"""
from pathlib import Path
import bz2
import lzma
import math
import re
import struct
import zlib
from collections import Counter

HERE = Path(__file__).resolve().parent
DAT_NEW = Path(r'<корень проекта>\FIRMWARE\ver new\FWUP0028 (2).DAT')
TRANS = bytes.maketrans(bytes(range(256)), bytes(255 - i for i in range(256)))
OUT = HERE / 'payload_0x2300274.txt'
START = 0x2300274
END = 0x2476dab


def H(b):
    c = Counter(b)
    n = len(b)
    return -sum(v / n * math.log2(v / n) for v in c.values())


SIGS = {
    'gzip': b'\x1f\x8b\x08', 'zlib 789c': b'\x78\x9c', 'zlib 7801': b'\x78\x01',
    'zlib 78da': b'\x78\xda', 'xz': bytes.fromhex('fd377a585a00'),
    'bz2': b'BZh9', 'lz4': bytes.fromhex('04224d18'), 'zstd': bytes.fromhex('28b52ffd'),
    'JPEG': b'\xff\xd8\xff', 'PNG': b'\x89PNG', 'GIF': b'GIF8', 'BMP': b'BM',
    'JFIF': b'JFIF', 'Exif': b'Exif', 'TIFF-le': b'II*\x00',
    'ELF': b'\x7fELF', 'FDL': b'FDL Font', 'cpio': b'070701',
    'Linux': b'Linux', 'ThreadX': b'ThreadX', 'MOVDC': b'MOVDC', 'X-H2': b'X-H2',
    'FUJIFILM': b'FUJIFILM', 'Fujifilm': b'Fujifilm', 'nul-long': b'\x00' * 16,
    'FFFFFF-long': b'\xff' * 16,
}


def probe(label, data, out):
    out.append(f'--- {label}: {len(data)} байт, H(0x2000)={H(data[:0x2000]):.2f} ---')
    for nm, pat in SIGS.items():
        hits = []
        s = 0
        while True:
            i = data.find(pat, s)
            if i < 0:
                break
            hits.append(hex(START + i))
            s = i + 1
            if len(hits) >= 5:
                hits.append('...')
                break
        if hits:
            out.append(f'    {nm}: {hits}')
    # распаковка
    for nm, fn in (('gzip', lambda d: zlib.decompressobj(31).decompress(d, 1 << 25)),
                   ('zlib', lambda d: zlib.decompressobj().decompress(d, 1 << 25)),
                   ('raw-deflate', lambda d: zlib.decompressobj(-15).decompress(d, 1 << 25)),
                   ('xz', lambda d: lzma.LZMADecompressor(format=lzma.FORMAT_XZ).decompress(d, 1 << 25)),
                   ('bz2', lambda d: bz2.BZ2Decompressor().decompress(d, 1 << 25))):
        try:
            got = fn(data)
            out.append(f'    распаковка {nm}: OK {len(got)} байт; {got[:80]!r}')
        except Exception:
            pass
    # визуально похожий текст (окна по 8 печатных)
    pat = re.compile(rb'[\x20-\x7e]{10,}')
    txt = [(START + m.start(), m.group()[:60]) for m in pat.finditer(data)]
    out.append(f'    текстовых окон >=10: {len(txt)}')
    for off, s in txt[:15]:
        out.append(f'      0x{off:x} {s!r}')
    # структура: доля нулей/ff и период
    out.append(f'    доля 0x00={data.count(0)/len(data)*100:.2f}% 0xFF={data.count(255)/len(data)*100:.2f}%')
    for p in (2, 4, 8, 16, 0x100, 0x1000):
        same = sum(1 for i in range(0, min(len(data) - p, 0x4000)) if data[i] == data[i + p])
        out.append(f'    период {p}: совпадений {same/min(len(data)-p,0x4000)*100:.1f}%')
    out.append('')


def main():
    dec = DAT_NEW.read_bytes().translate(TRANS)
    blob = dec[START:END]
    inv = bytes(c ^ 0xff for c in blob)
    out = [f'payload @0x{START:x}..0x{END:x}, размер {len(blob)} (0x{len(blob):x})', '']
    probe('как есть (после XOR 0xFF всего файла)', blob, out)
    probe('инвертированный (XOR 0xFF ещё раз)', inv, out)
    out.append('=== первые 0x100 каждого варианта ===')
    for nm, d in (('как есть', blob), ('инверт', inv)):
        out.append(f'  {nm}:')
        for o in range(0, 0x100, 16):
            out.append(f'   {o:04x}  {d[o:o+16].hex(" ")}  |' +
                       ''.join(chr(c) if 32 <= c < 127 else '.' for c in d[o:o+16]) + '|')
    OUT.write_text('\n'.join(out) + '\n', encoding='utf-8')
    print('written', OUT)


if __name__ == '__main__':
    main()
