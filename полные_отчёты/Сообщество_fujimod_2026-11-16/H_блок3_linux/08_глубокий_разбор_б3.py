"""Глубокий разбор блока 3: выравнивание, ASCII/UTF-16, картина 4-байтовых групп,
периодичность, дампы ключевых страниц, попытки распаковки.

Только чтение blocks/*.bin.
"""
from pathlib import Path
import re
import struct
import zlib
import math
from collections import Counter

HERE = Path(__file__).resolve().parent
BLOCKS = HERE.parent.parent / 'Сравнение_версий_2026-11-16' / 'blocks'
B3 = BLOCKS / 'X-H2_5.33_b3_0x24a0274.bin'
OUT = HERE / 'B3_глубокий_разбор.txt'

ASCII = re.compile(rb'[\x20-\x7e]{6,}')
UTF16 = re.compile(rb'(?:[\x20-\x7e]\x00){5,}')


def hexdump(data, start, n, width=16):
    lines = []
    for o in range(start, min(start + n, len(data)), width):
        chunk = data[o:o + width]
        h = ' '.join(f'{c:02x}' for c in chunk)
        a = ''.join(chr(c) if 32 <= c < 127 else '.' for c in chunk)
        lines.append(f'{o:08x}  {h:<{width*3}}  {a}')
    return lines


def main():
    data = B3.read_bytes()
    out = [f'блок 3 X-H2 5.33: 0x{len(data):x} байт', '']

    # 1. ASCII / UTF-16
    asc = list(ASCII.finditer(data))
    u16 = list(UTF16.finditer(data))
    out.append(f'ASCII-строк (>=6) {len(asc)}; UTF-16LE (>=5 симв.) {len(u16)}')
    out.append('первые 40 ASCII:')
    for m in asc[:40]:
        out.append(f'  0x{m.start():07x} {m.group()[:70]!r}')
    out.append('первые 20 UTF-16:')
    for m in u16[:20]:
        out.append(f'  0x{m.start():07x} {m.group().decode("utf-16-le", "replace")[:60]!r}')
    out.append('')

    # 2. картина 4-байтовых групп: доля групп с данным байтом = 0xff
    for align in range(4):
        grp = data[align:]
        n = len(grp) // 4
        c3 = sum(1 for k in range(n) if grp[k * 4 + 3] == 0xff)
        c0 = sum(1 for k in range(n) if grp[k * 4 + 0] == 0xff)
        out.append(f'выравнивание {align}: групп {n}, byte[3]==0xff {c3} ({c3/max(n,1)*100:.1f}%), '
                   f'byte[0]==0xff {c0} ({c0/max(n,1)*100:.1f}%)')
    out.append('')

    # 3. пословная статистика: доля слов-значений, у которых старший байт 0
    n = len(data) // 4
    words = struct.unpack_from(f'<{n}I', data, 0)
    hi = Counter(w >> 24 for w in words)
    out.append('старший байт 32-битных слов (топ-10): ' +
               ', '.join(f'{k:02x}:{v}' for k, v in hi.most_common(10)))
    small = sum(1 for w in words if w < 0x10000)
    out.append(f'слов < 0x10000: {small} ({small/n*100:.1f}%)')
    out.append('')

    # 4. периодичность: доля совпадающих байт при сдвиге p
    out.append('автокорреляция первых 0x20000 байт: сдвиг -> доля совпадений')
    head = data[:0x20000]
    for p in list(range(1, 25)) + [32, 48, 64, 96, 128, 256, 512, 1024, 4096, 0x4000]:
        same = sum(1 for i in range(0, min(len(head) - p, 0x8000)) if head[i] == head[i + p])
        out.append(f'  p={p}: {same/min(len(head)-p,0x8000)*100:.1f}%')
    out.append('')

    # 5. дампы
    for off in (0x1000, 0x2000, 0x3000, 0x8000, 0x1c000, 0x20000, 0x100000, 0x200000,
                0x300000, 0x400000, 0x600000, 0x6f0000, 0x70c000, len(data) - 0x100):
        out.append(f'--- дамп 0x{off:x} ---')
        out += hexdump(data, off, 0x60)
        out.append('')

    # 6. попытки распаковки целых и частичных потоков
    out.append('--- попытки распаковки ---')
    for off in range(0, min(len(data), 0x20000), 4):
        head = data[off:off + 2]
        if head in (b'\x78\x9c', b'\x78\x01', b'\x78\xda'):
            try:
                d = zlib.decompressobj()
                got = d.decompress(data[off:off + (1 << 20)], 1 << 20)
                out.append(f'  zlib @0x{off:x}: OK {len(got)} байт, начало {got[:60]!r}')
            except Exception:
                pass
    # LZ4 frame
    i = data.find(b'\x04\x22\x4d\x18')
    out.append(f'  LZ4 frame magic: {hex(i) if i>=0 else "нет"}')

    # 7. поиск целевых констант (вдруг не сжато)
    out.append('--- целевые константы в блоке 3 ---')
    for label, pats in {
        '0xFF970000': [struct.pack('<I', 0xFF970000), struct.pack('>I', 0xFF970000)],
        '0x10030001': [struct.pack('<I', 0x10030001), struct.pack('>I', 0x10030001)],
        '0xFF90C300': [struct.pack('<I', 0xFF90C300), struct.pack('>I', 0xFF90C300)],
        '0xFF90E100': [struct.pack('<I', 0xFF90E100)],
        '0x4c2ff14': [struct.pack('<I', 0x4c2ff14), struct.pack('<Q', 0x4c2ff14)],
        '0x4daa6e8': [struct.pack('<I', 0x4daa6e8), struct.pack('<Q', 0x4daa6e8)],
        'MOVDC': [b'MOVDC'], 'movdc': [b'movdc'],
    }.items():
        res = []
        for p in pats:
            s = 0
            while True:
                i = data.find(p, s)
                if i < 0:
                    break
                res.append(hex(i))
                s = i + 1
                if len(res) > 6:
                    break
        out.append(f'  {label}: {res if res else "нет"}')

    OUT.write_text('\n'.join(out) + '\n', encoding='utf-8')
    print('written', OUT)


if __name__ == '__main__':
    main()
