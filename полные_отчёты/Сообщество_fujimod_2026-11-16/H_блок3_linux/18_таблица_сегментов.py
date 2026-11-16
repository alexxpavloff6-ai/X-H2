"""Разбор «таблицы сегментов» блока 3: 16-байтовые записи в районе 0x1c000.

Проверяет гипотезу: u64-поле = смещение от базы 0x8a0000 (тогда все записи попадают
внутрь блока 3). Только чтение blocks/*.bin.
"""
from pathlib import Path
import struct

HERE = Path(__file__).resolve().parent
BLOCKS = HERE.parent.parent / 'Сравнение_версий_2026-11-16' / 'blocks'
OUT = HERE / 'B3_таблица_сегментов.txt'
CAND_BASES = [0x8a0000, 0x800000, 0x8c0000]


def main():
    b3 = (BLOCKS / 'X-H2_5.33_b3_0x24a0274.bin').read_bytes()
    out = [f'блок 3: 0x{len(b3):x} байт']
    found = []
    for start in range(0x18000, 0x28000, 16):
        rec = b3[start:start + 16]
        if len(rec) < 16:
            break
        off, a, b, c, d = struct.unpack('<Q4H', rec)
        if 0x800000 <= off <= 0x900000 and c == 1 and d == 0 and 0 < a < 0x100 and 0 < b < 0x100:
            found.append((start, off, a, b, c, d))
    out.append(f'записей {{u64 off, u16 a, u16 b, u16 1, u16 0}} с off в 0x800000..0x900000: {len(found)}')
    if found:
        out.append(f'   первая запись на 0x{found[0][0]:x}, последняя на 0x{found[-1][0]:x}')
        offs = [f[1] for f in found]
        out.append(f'   min off=0x{min(offs):x} max off=0x{max(offs):x}')
        for base in CAND_BASES:
            rel = [o - base for o in offs]
            inside = sum(1 for r in rel if 0 <= r < len(b3))
            out.append(f'   база 0x{base:x}: внутри блока {inside}/{len(rel)}, '
                       f'диапазон смещений 0x{min(rel):x}..0x{max(rel):x}')
        out.append('   первые 24 записи (off, a, b, off-0x8a0000):')
        for s, off, a, b, c, d in found[:24]:
            out.append(f'    0x{s:06x}: off=0x{off:08x} a=0x{a:04x}({a}) b=0x{b:04x}({b}) '
                       f'-> rel=0x{off-0x8a0000:x}')
        out.append('')
        out.append('   контекст первой записи:')
        for o in range(max(0, found[0][0] - 0x20), found[0][0] + 0x80, 16):
            out.append(f'    0x{o:06x}  {b3[o:o+16].hex(" ")}')
        # что лежит по относительным адресам
        out.append('')
        out.append('   что лежит по найденным относительным адресам (первые 32 байта):')
        for s, off, a, b, c, d in found[:12]:
            r = off - 0x8a0000
            if 0 <= r < len(b3) - 32:
                out.append(f'    rel=0x{r:06x}: {b3[r:r+32].hex(" ")}')
    OUT.write_text('\n'.join(out) + '\n', encoding='utf-8')
    print('written', OUT)


if __name__ == '__main__':
    main()
