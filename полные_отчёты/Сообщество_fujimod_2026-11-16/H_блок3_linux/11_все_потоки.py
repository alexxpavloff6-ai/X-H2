"""Полный поиск FFLZ-потоков в DAT с ЛЮБЫМ размером страницы + попытки распаковки
иных форматов в подозрительных зонах.

Только чтение DAT.
"""
from pathlib import Path
import bz2
import gzip
import io
import lzma
import struct
import zlib

HERE = Path(__file__).resolve().parent
DAT_NEW = Path(r'<корень проекта>\FIRMWARE\ver new\FWUP0028 (2).DAT')
TRANS = bytes.maketrans(bytes(range(256)), bytes(255 - i for i in range(256)))
OUT = HERE / 'DAT_все_потоки.txt'


def unpack_fflz(data, off, u, c):
    packed = memoryview(data)[off:off + c]
    pos, result = 20, bytearray()
    while pos < c:
        token = packed[pos]
        pos += 1
        if token < 128:
            if pos + token > c:
                raise ValueError('literal exceeds input')
            result.extend(packed[pos:pos + token])
            pos += token
        else:
            if pos >= c:
                raise ValueError('match exceeds input')
            second = packed[pos]
            pos += 1
            length = second & 15
            distance = ((token & 127) << 4) | (second >> 4)
            if not 0 < length <= distance <= len(result):
                raise ValueError('bad back reference')
            start = len(result) - distance
            result.extend(result[start:start + length])
        if len(result) > u:
            raise ValueError('output exceeds declared size')
    short = u - len(result)
    if 0 < short <= 127 and c % 16384 == 0:
        result.extend(bytes(short))
    if len(result) != u:
        raise ValueError(f'decoded size mismatch {len(result)} != {u}')
    return bytes(result)


def scan_fflz(dec, out):
    found = []
    n = len(dec)
    for o in range(0, n - 20, 4):
        u, c, pages, page_size, align = struct.unpack_from('<5I', dec, o)
        if not (0 < page_size <= 0x100000) or page_size & (page_size - 1):
            continue
        if not (0x1000 <= page_size <= 0x100000):
            continue
        if not (0x100 <= c <= 64 << 20) or c > n - o:
            continue
        if not (c < u <= 1 << 28):
            continue
        if (c + page_size - 1) // page_size != pages:
            continue
        if align not in (0, 1, 2, 4, 8, 16, 0x1000):
            continue
        try:
            data = unpack_fflz(dec, o, u, c)
        except Exception:
            continue
        found.append((o, u, c, pages, page_size, align, data))
        out.append(f'  FFLZ @ 0x{o:x}: usize=0x{u:x} csize=0x{c:x} pages={pages} '
                   f'page=0x{page_size:x} align={align}')
        out.append(f'     начало: {data[:64].hex(" ")}')
    return found


def try_other(dec, off, out, label):
    out.append(f'--- попытки распаковки @0x{off:x} ({label}) ---')
    seg = dec[off:]
    out.append(f'   первые 32: {seg[:32].hex(" ")}')
    for name, fn in (
        ('gzip', lambda d: zlib.decompressobj(31).decompress(d, 1 << 24)),
        ('zlib', lambda d: zlib.decompressobj().decompress(d, 1 << 24)),
        ('raw-deflate', lambda d: zlib.decompressobj(-15).decompress(d, 1 << 24)),
        ('xz', lambda d: lzma.LZMADecompressor(format=lzma.FORMAT_XZ).decompress(d, 1 << 24)),
        ('alone-lzma', lambda d: lzma.LZMADecompressor(format=lzma.FORMAT_ALONE).decompress(d, 1 << 24)),
        ('bz2', lambda d: bz2.BZ2Decompressor().decompress(d, 1 << 24)),
    ):
        try:
            got = fn(seg)
            out.append(f'  {name}: OK {len(got)} байт; {got[:80]!r}')
        except Exception as exc:  # noqa: BLE001
            out.append(f'  {name}: нет ({type(exc).__name__})')
    # энтропия первых 4 КиБ
    import collections
    import math
    def H(b):
        c = collections.Counter(b)
        n = len(b)
        return -sum(v / n * math.log2(v / n) for v in c.values())
    out.append(f'  энтропия первых 4КиБ: {H(seg[:0x1000]):.2f}')


def main():
    dec = DAT_NEW.read_bytes().translate(TRANS)
    out = ['поиск FFLZ любого размера страницы во всём DAT:']
    found = scan_fflz(dec, out)
    out.append(f'всего найдено: {len(found)}')
    out.append('')
    for off, label in ((0x22ffdab, 'зона между бл.2 и бл.3, H=6.63'),
                       (0x22c5dab, 'зона H=4.37'),
                       (0x22bfdab, 'зона H=0.97'),
                       (0x22d8dab, 'зона H=1.76'),
                       (0x6840274, 'хвост: таблица указателей'),
                       (0x6860274, 'хвост H=3.24'),
                       (0x68e5274, 'хвост H=4.81'),
                       (0x6924274, 'хвост H=4.47'),
                       (0x293f75c, 'зона после бл.3 H=0.98'),
                       (0x377f75c, 'зона после бл.3 H=3.54'),
                       (0x3b7f75c, 'зона после бл.3 H=4.22'),
                       (0x0, 'начало DAT')):
        try_other(dec, off, out, label)
    # сохрани все распакованные FFLZ-потоки больших размеров
    (HERE / 'распаковано').mkdir(exist_ok=True)
    for k, (o, u, c, pages, pgs, al, data) in enumerate(found):
        if u > 0x40000:
            (HERE / 'распаковано' / f'fflz_0x{o:x}_{u}.bin').write_bytes(data)
    OUT.write_text('\n'.join(out) + '\n', encoding='utf-8')
    print('written', OUT)


if __name__ == '__main__':
    main()
