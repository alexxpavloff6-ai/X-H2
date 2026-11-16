"""Извлечение rootfs Linux из сырой области DAT (gzip-CPIO @ 0x42dfdcc) в свою папку.

Только чтение DAT; распаковка в H_блок3_linux/rootfs/.
"""
from pathlib import Path
import gzip
import io
import struct
import zlib

HERE = Path(__file__).resolve().parent
DAT_NEW = Path(r'<корень проекта>\FIRMWARE\ver new\FWUP0028 (2).DAT')
TRANS = bytes.maketrans(bytes(range(256)), bytes(255 - i for i in range(256)))
GZ_OFF = 0x42dfdcc
OUTDIR = HERE / 'rootfs'
LIST = HERE / 'rootfs_список.txt'


def main():
    raw = DAT_NEW.read_bytes()
    dec = raw.translate(TRANS)
    d = zlib.decompressobj(31)
    cpio = d.decompress(dec[GZ_OFF:])
    used = len(dec) - GZ_OFF - len(d.unused_data)
    print(f'распаковано {len(cpio)} байт (0x{len(cpio):x}), сжатый поток {used} байт '
          f'(0x{GZ_OFF:x}..0x{GZ_OFF+used:x})')
    (HERE / 'rootfs.cpio').write_bytes(cpio)

    pos = 0
    entries = []
    while True:
        if cpio[pos:pos + 6] not in (b'070701', b'070702'):
            print('не CPIO по смещению', hex(pos), cpio[pos:pos + 16].hex())
            break
        hdr = cpio[pos:pos + 110]
        f = [int(hdr[6 + i * 8:14 + i * 8], 16) for i in range(13)]
        ino, mode, uid, gid, nlink, mtime, filesize, devmaj, devmin, rdevmaj, rdevmin, namesize, check = f
        name = cpio[pos + 110:pos + 110 + namesize - 1].decode('latin1')
        hdrlen = (110 + namesize + 3) & ~3
        doff = pos + hdrlen
        entries.append((name, mode, filesize, doff, mtime, nlink, rdevmaj, rdevmin))
        pos = doff + ((filesize + 3) & ~3)
        if name == 'TRAILER!!!':
            break
    print(f'файлов: {len(entries)}, конец CPIO 0x{pos:x}')

    lines = ['mode\tразмер\tсмещение\tимя']
    total = 0
    OUTDIR.mkdir(exist_ok=True)
    for name, mode, size, doff, mtime, nlink, rdevmaj, rdevmin in entries:
        kind = mode & 0o170000
        k = {0o100000: '-', 0o040000: 'd', 0o120000: 'l', 0o060000: 'b', 0o020000: 'c',
             0o010000: 'p', 0o140000: 's'}.get(kind, '?')
        lines.append(f'{k}{mode & 0o7777:04o}\t{size}\t0x{doff:x}\t{name}')
        total += size
        if name == 'TRAILER!!!':
            continue
        rel = name.lstrip('/').replace('\\', '/')
        if not rel or rel.startswith('..'):
            continue
        dst = OUTDIR / rel
        try:
            if kind == 0o040000:
                dst.mkdir(parents=True, exist_ok=True)
            elif kind == 0o120000:
                dst.parent.mkdir(parents=True, exist_ok=True)
                dst.write_bytes(cpio[doff:doff + size])
            elif kind == 0o100000:
                dst.parent.mkdir(parents=True, exist_ok=True)
                dst.write_bytes(cpio[doff:doff + size])
        except OSError as exc:
            print('ошибка записи', name, exc)
    LIST.write_text('\n'.join(lines) + '\n', encoding='utf-8')
    print(f'суммарный размер данных {total} байт; список в rootfs_список.txt')


if __name__ == '__main__':
    main()
