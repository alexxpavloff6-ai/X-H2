"""Структура блока 3: карта заполненности по страницам 0x4000, энтропия, поиск payload'ов.

Только чтение blocks/*.bin.
"""
from pathlib import Path
import math
import struct
from collections import Counter

HERE = Path(__file__).resolve().parent
BLOCKS = HERE.parent.parent / 'Сравнение_версий_2026-11-16' / 'blocks'
OUT = HERE / 'B3_карта.txt'

FILES = {
    'X-H2_5.33': BLOCKS / 'X-H2_5.33_b3_0x24a0274.bin',
    'X-H2_5.30': BLOCKS / 'X-H2_5.30_b3_0x24a0274.bin',
    'X-H2S_7.31': BLOCKS / 'X-H2S_7.31_b3_0x24a0274.bin',
    'X-T5_4.32': BLOCKS / 'X-T5_4.32_b3_0x24a0274.bin',
}

PAGE = 0x4000


def entropy(b):
    if not b:
        return 0.0
    c = Counter(b)
    n = len(b)
    return -sum((v / n) * math.log2(v / n) for v in c.values())


def main():
    out = []
    for name, path in FILES.items():
        data = path.read_bytes()
        out.append(f'=== {name} size=0x{len(data):x} ===')
        nz = sum(1 for c in data if c)
        out.append(f'  ненулевых байт: {nz} ({nz/len(data)*100:.2f}%)  нулевых: {len(data)-nz}')
        out.append(f'  энтропия всего блока: {entropy(data):.3f} бит/байт')
        pages = (len(data) + PAGE - 1) // PAGE
        # карта страниц
        rows = []
        for p in range(pages):
            chunk = data[p * PAGE:(p + 1) * PAGE]
            nzc = sum(1 for c in chunk if c)
            e = entropy(chunk)
            rows.append((p, nzc, e))
        # сводка: непрерывные зоны "заполнено" (>50% ненулевых)
        zones = []
        cur = None
        for p, nzc, e in rows:
            busy = nzc > PAGE // 2
            if busy and cur is None:
                cur = p
            elif not busy and cur is not None:
                zones.append((cur, p - 1))
                cur = None
        if cur is not None:
            zones.append((cur, rows[-1][0]))
        out.append(f'  страниц по 0x4000: {pages}; зон с >50% ненулевых: {len(zones)}')
        for a, z in zones[:40]:
            out.append(f'    зона 0x{a*PAGE:x}..0x{(z+1)*PAGE:x} ({z-a+1} стр.)')
        if len(zones) > 40:
            out.append(f'    ... ещё {len(zones)-40} зон')
        # распределение энтропии по страницам
        out.append('  первые 24 страницы: p, ненулевых, энтропия')
        for p, nzc, e in rows[:24]:
            out.append(f'    {p:4d} 0x{p*PAGE:07x}  nz={nzc:5d}  H={e:.2f}')
        # последняя часть
        out.append('  последние 8 страниц:')
        for p, nzc, e in rows[-8:]:
            out.append(f'    {p:4d} 0x{p*PAGE:07x}  nz={nzc:5d}  H={e:.2f}')
        # хвост файла
        out.append(f'  хвост 0x{len(data)-0x80:x}: {data[-0x80:].hex(" ")}')
        out.append('')
    OUT.write_text('\n'.join(out) + '\n', encoding='utf-8')
    print(f'written {OUT}')


if __name__ == '__main__':
    main()
