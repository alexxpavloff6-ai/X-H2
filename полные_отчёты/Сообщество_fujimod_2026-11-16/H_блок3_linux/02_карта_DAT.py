"""Карта DAT: границы FFLZ-блоков, сырые (не-FFLZ) области и сигнатуры в них.

Только чтение DAT. Пишет карту в свою папку.
"""
from pathlib import Path
import struct

HERE = Path(__file__).resolve().parent
DAT_NEW = Path(r'<корень проекта>\FIRMWARE\ver new\FWUP0028 (2).DAT')
DAT_OLD = Path(r'<корень проекта>\FIRMWARE\ver 5.30\FWUP0028.DAT')
OUT = HERE / 'DAT_карта.txt'

TRANS = bytes.maketrans(bytes(range(256)), bytes(255 - i for i in range(256)))


def fflz_blocks(dec):
    out = []
    start = 0
    needle = bytes.fromhex('0040000004000000')
    while True:
        i = dec.find(needle, start)
        if i < 0:
            break
        off = i - 12
        if off >= 0:
            u, c, n, pg, align = struct.unpack_from('<5I', dec, off)
            if 20 < c < u < 512 * 2**20 and (c + 16383) // 16384 == n and off + c <= len(dec) - 72:
                out.append({'off': off, 'u': u, 'c': c, 'pages': n, 'page': pg, 'align': align,
                            'end': off + c})
                start = off + c
                continue
        start = i + 1
    return out


SIGS = {
    'Linux version': b'Linux version',
    'ARM\\x64 Image magic': b'ARM\x64',
    'DTB': bytes.fromhex('d00dfeed'),
    'CPIO 070701': b'070701',
    'IKCFG_ST': b'IKCFG_ST',
    'gzip': b'\x1f\x8b\x08',
    'ELF': b'\x7fELF',
    'FFLZ hdr': bytes.fromhex('0040000004000000'),
    'uImage': bytes.fromhex('27051956'),
    'XZ': bytes.fromhex('fd377a585a00'),
    'zstd': bytes.fromhex('28b52ffd'),
    'lz4': bytes.fromhex('04224d18'),
    'bzip2': b'BZh9',
    'squashfs': b'hsqs',
    'cramfs': bytes.fromhex('453dcd28'),
    'FFLZ-any 5u32 plausible': None,
    'ext2/3/4 sb': bytes.fromhex('53ef'),
    'DOS MZ': b'MZ\x90',
    'ThreadX strings': b'ThreadX',
    'console=': b'console=',
    'rootfs': b'rootfs',
}


def scan(data, region_name, base_off, out, limit=6):
    for name, needle in SIGS.items():
        if needle is None:
            continue
        hits = []
        s = 0
        while True:
            i = data.find(needle, s)
            if i < 0:
                break
            hits.append(hex(base_off + i))
            s = i + 1
            if len(hits) >= limit:
                hits.append('...')
                break
        if hits:
            out.append(f'    {name}: {len(hits)} -> {hits}')


def main():
    out = []
    for label, dat in (('5.33', DAT_NEW), ('5.30', DAT_OLD)):
        raw = dat.read_bytes()
        dec = raw.translate(TRANS)
        out.append(f'===== DAT {label}: {dat.name}  size={len(raw)} (0x{len(raw):x}) =====')
        bl = fflz_blocks(dec)
        out.append('  FFLZ-блоки:')
        prev_end = 0
        gaps = []
        for k, b in enumerate(bl):
            out.append(f'   b{k}: off=0x{b["off"]:x} csize=0x{b["c"]:x} usize=0x{b["u"]:x} '
                       f'pages={b["pages"]} page=0x{b["page"]:x} align={b["align"]} end=0x{b["end"]:x} '
                       f'sha_decode=?')
            if b['off'] > prev_end:
                gaps.append((prev_end, b['off']))
            prev_end = b['end']
        if prev_end < len(raw) - 72:
            gaps.append((prev_end, len(raw) - 72))
        out.append(f'  сырых областей (вне FFLZ, до подписи): {len(gaps)}')
        for (a, z) in gaps:
            out.append(f'   RAW 0x{a:x}..0x{z:x}  len=0x{z-a:x} ({z-a})')
            scan(dec[a:z], f'raw_{a:x}', a, out, limit=8)
        out.append('')
        # особо: DTB / ELF контекст
        for mag, nm in ((bytes.fromhex('d00dfeed'), 'DTB'), (b'\x7fELF', 'ELF'), (b'Linux version', 'LinuxVersion')):
            i = dec.find(mag)
            while i >= 0:
                out.append(f'  {nm} @ 0x{i:x}: {dec[i:i+64].hex(" ")}  |' +
                           ''.join(chr(c) if 32 <= c < 127 else '.' for c in dec[i:i+64]) + '|')
                i = dec.find(mag, i + 1)
                if i >= 0 and nm != 'DTB':
                    break
        out.append('')
    OUT.write_text('\n'.join(out) + '\n', encoding='utf-8')
    print(f'written {OUT}')


if __name__ == '__main__':
    main()
