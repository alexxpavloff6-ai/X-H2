"""Разбор мест в заголовке DAT, где встретились 0xFF90C300 и 0x10030001.

Возможно, это таблица «адрес=значение» (data-driven инициализация периферии).
Только чтение DAT.
"""
from pathlib import Path
import struct

HERE = Path(__file__).resolve().parent
DAT_NEW = Path(r'<корень проекта>\FIRMWARE\ver new\FWUP0028 (2).DAT')
TRANS = bytes.maketrans(bytes(range(256)), bytes(255 - i for i in range(256)))
OUT = HERE / 'DAT_заголовок_таблицы.txt'


def hexdump(data, start, n, width=16):
    lines = []
    for o in range(start, min(start + n, len(data)), width):
        chunk = data[o:o + width]
        h = ' '.join(f'{c:02x}' for c in chunk)
        a = ''.join(chr(c) if 32 <= c < 127 else '.' for c in chunk)
        lines.append(f'{o:08x}  {h:<{width*3}}  {a}')
    return lines


def main():
    dec = DAT_NEW.read_bytes().translate(TRANS)
    out = []
    for center, label in ((0x9464, '0xFF90C300 (LE) #1'), (0x9736, '0x10030001 (LE)'),
                          (0x1b43d, '0x10030001 (BE)'), (0x3816c, '0xFF90C300 (LE) #2'),
                          (0x0, 'начало файла')):
        a = max(0, center - 0x80) & ~0xf
        out.append(f'=== {label} @0x{center:x}: дамп 0x{a:x}.. ===')
        out += hexdump(dec, a, 0x180)
        out.append('  u32:')
        for k in range(a, a + 0x180, 16):
            vals = struct.unpack_from('<4I', dec, k)
            out.append(f'   {k:08x}: ' + ' '.join(f'{v:08x}' for v in vals))
        out.append('')
    OUT.write_text('\n'.join(out) + '\n', encoding='utf-8')
    print('written', OUT)


if __name__ == '__main__':
    main()
