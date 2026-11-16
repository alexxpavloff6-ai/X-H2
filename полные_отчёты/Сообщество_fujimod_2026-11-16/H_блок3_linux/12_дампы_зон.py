"""Дампы начал подозрительных зон в сырых областях DAT (после пропуска 0x00/0xFF-заливки)."""
from pathlib import Path
import struct

HERE = Path(__file__).resolve().parent
DAT_NEW = Path(r'<корень проекта>\FIRMWARE\ver new\FWUP0028 (2).DAT')
TRANS = bytes.maketrans(bytes(range(256)), bytes(255 - i for i in range(256)))
OUT = HERE / 'DAT_дампы_зон.txt'

OFFSETS = [0x22c5dab, 0x22ffdab, 0x2476d00,
           0x293f75c, 0x297775c, 0x29ff75c, 0x2a5f75c, 0x2abf75c, 0x2bdf75c,
           0x371f75c, 0x377f75c, 0x38df75c, 0x3b7f75c, 0x3c3f75c,
           0x6840274, 0x6849274, 0x6860274, 0x6898274, 0x68e5274, 0x690f274, 0x6924274]


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
    for off in OFFSETS:
        # пропустить заливку
        p = off
        while p < off + 0x20000 and dec[p] in (0, 0xff) and dec[p + 1] in (0, 0xff) \
                and dec[p + 2] in (0, 0xff) and dec[p + 3] in (0, 0xff):
            p += 4
        out.append(f'=== 0x{off:x}: первые непустые данные с 0x{p:x} (сдвиг 0x{p-off:x}) ===')
        out += hexdump(dec, p, 0x80)
        # как 32-битные слова
        words = struct.unpack_from('<16I', dec, p)
        out.append('  u32: ' + ' '.join(f'{w:08x}' for w in words))
        fl = struct.unpack_from('<16f', dec, p)
        out.append('  f32: ' + ' '.join(f'{w:.3g}' for w in fl))
        out.append('')
    OUT.write_text('\n'.join(out) + '\n', encoding='utf-8')
    print('written', OUT)


if __name__ == '__main__':
    main()
