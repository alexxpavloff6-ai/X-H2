"""Разбор заголовка/таблицы сегментов блока 3 (Linux/системная часть) X-H2.

Только чтение blocks/*.bin. Пишет текстовый дамп в свою папку.
"""
from pathlib import Path
import struct
import sys

HERE = Path(__file__).resolve().parent
BLOCKS = HERE.parent.parent / 'Сравнение_версий_2026-11-16' / 'blocks'
OUT = HERE / 'B3_заголовок.txt'

FILES = {
    'X-H2_5.33': BLOCKS / 'X-H2_5.33_b3_0x24a0274.bin',
    'X-H2_5.30': BLOCKS / 'X-H2_5.30_b3_0x24a0274.bin',
    'X-H2S_7.31': BLOCKS / 'X-H2S_7.31_b3_0x24a0274.bin',
    'X-T5_4.32': BLOCKS / 'X-T5_4.32_b3_0x24a0274.bin',
}


def hexdump(data, start, n, width=16):
    lines = []
    for o in range(start, min(start + n, len(data)), width):
        chunk = data[o:o + width]
        h = ' '.join(f'{c:02x}' for c in chunk)
        a = ''.join(chr(c) if 32 <= c < 127 else '.' for c in chunk)
        lines.append(f'{o:08x}  {h:<{width*3}}  {a}')
    return lines


def main():
    out = []
    for name, path in FILES.items():
        data = path.read_bytes()
        out.append(f'=== {name}  size=0x{len(data):x} ({len(data)}) ===')
        out.append('-- первые 0x200 байт --')
        out += hexdump(data, 0, 0x200)
        out.append('')
        # 12-байтовые записи
        out.append('-- интерпретация как 12-байтовых записей (3 x u32) --')
        for i in range(0, 0x120, 12):
            a, b, c = struct.unpack_from('<3I', data, i)
            out.append(f'{i:04x}: {a:08x} {b:08x} {c:08x}   a={a} b={b} c={c}')
        out.append('')
        out.append('-- интерпретация как 12-байтовых записей (u16 x6) --')
        for i in range(0, 0x120, 12):
            v = struct.unpack_from('<6H', data, i)
            out.append(f'{i:04x}: ' + ' '.join(f'{x:04x}({x})' for x in v))
        out.append('')
        # частоты байтов в первом 0x1000
        head = data[:0x1000]
        out.append('-- гистограмма байтов первых 0x1000 (топ-16) --')
        from collections import Counter
        cnt = Counter(head)
        for byte, n in cnt.most_common(16):
            out.append(f'  {byte:02x}: {n}')
        out.append('')
        # ищем сигнатуры по всему блоку
        sigs = {
            'gzip 1f8b08': b'\x1f\x8b\x08',
            'ELF': b'\x7fELF',
            'DTB d00dfeed': bytes.fromhex('d00dfeed'),
            'CPIO 070701': b'070701',
            'CPIO 070702': b'070702',
            'CPIO 070707': b'070707',
            'IKCFG_ST': b'IKCFG_ST',
            'Linux version': b'Linux version',
            'uImage 27051956': bytes.fromhex('27051956'),
            'ARM64 Image magic': b'ARM\x64',
            'LZ4 04224d18': bytes.fromhex('04224d18'),
            'LZMA 5d0000': b'\x5d\x00\x00',
            'XZ fd377a585a00': bytes.fromhex('fd377a585a00'),
            'bzip2 BZh': b'BZh',
            'zstd 28b52ffd': bytes.fromhex('28b52ffd'),
            'FFLZ 0040000004000000': bytes.fromhex('0040000004000000'),
            'squashfs hsqs': b'hsqs',
            'cramfs': b'\x45\x3d\xcd\x28',
            'ubifs': b'\x31\x18\x03\x00',
            'ext4': b'\x53\xef',
            'FDT strings: arm,cortex-a53': b'arm,cortex-a53',
            'init=/': b'init=/',
            'console=tty': b'console=tty',
            'root=/dev': b'root=/dev',
            'mem=': b'mem=',
        }
        out.append('-- сигнатуры (все вхождения, до 8 на сигнатуру) --')
        for sn, needle in sigs.items():
            hits = []
            start = 0
            while True:
                i = data.find(needle, start)
                if i < 0:
                    break
                hits.append(hex(i))
                start = i + 1
                if len(hits) >= 8:
                    break
            out.append(f'  {sn}: {len(hits)} {hits}')
        out.append('')
    OUT.write_text('\n'.join(out) + '\n', encoding='utf-8')
    print(f'written {OUT}')


if __name__ == '__main__':
    main()
