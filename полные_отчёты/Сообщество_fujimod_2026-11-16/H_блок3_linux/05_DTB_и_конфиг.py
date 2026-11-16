"""Полный разбор DTB из сырой области DAT + поиск адресов MOVDC/mailbox в дереве.

Только чтение DAT. Пишет в свою папку: DTB_дерево.txt, извлечённые артефакты.
"""
from pathlib import Path
import gzip
import struct
import zlib

HERE = Path(__file__).resolve().parent
DAT_NEW = Path(r'<корень проекта>\FIRMWARE\ver new\FWUP0028 (2).DAT')
DAT_OLD = Path(r'<корень проекта>\FIRMWARE\ver 5.30\FWUP0028.DAT')
TRANS = bytes.maketrans(bytes(range(256)), bytes(255 - i for i in range(256)))
DTB_OFF = 0x3c40274
OUT = HERE / 'DTB_дерево.txt'

FDT_BEGIN_NODE, FDT_END_NODE, FDT_PROP, FDT_NOP, FDT_END = 1, 2, 3, 4, 9


def be32(d, o):
    return struct.unpack_from('>I', d, o)[0]


def parse(blob):
    magic, totalsize, off_struct, off_strings, off_rsv, version, last_comp, boot_cpuid, size_strings, size_struct = \
        struct.unpack_from('>10I', blob, 0)
    strings = blob[off_strings:off_strings + size_strings]
    nodes = []
    path = []
    pos = off_struct
    while pos < len(blob):
        tok = be32(blob, pos)
        pos += 4
        if tok == FDT_BEGIN_NODE:
            end = blob.index(b'\0', pos)
            name = blob[pos:end].decode('latin1')
            pos = (end + 4) & ~3
            path.append(name)
            nodes.append(('node', '/'.join(path), []))
        elif tok == FDT_END_NODE:
            if path:
                path.pop()
        elif tok == FDT_PROP:
            ln, nameoff = struct.unpack_from('>2I', blob, pos)
            pos += 8
            val = blob[pos:pos + ln]
            pos = (pos + ln + 3) & ~3
            nm = strings[nameoff:strings.index(b'\0', nameoff)].decode('latin1') if nameoff < len(strings) else '?'
            nodes.append(('prop', '/'.join(path), (nm, ln, val)))
        elif tok == FDT_NOP:
            continue
        elif tok == FDT_END:
            break
    return nodes, totalsize


def printable(val):
    if not val:
        return '""'
    if all(32 <= c < 127 or c in (0, 9, 10) for c in val):
        txt = val.decode('latin1')
        parts = txt.split('\0')
        if len(parts) > 1:
            return ' '.join(repr(p) for p in parts if p)
        return repr(txt)
    if len(val) % 4 == 0:
        cells = struct.unpack(f'>{len(val)//4}I', val)
        return '<' + ' '.join(f'0x{c:x}' for c in cells) + '>'
    return val.hex(' ')


def main():
    raw = DAT_NEW.read_bytes()
    dec = raw.translate(TRANS)
    blob = dec[DTB_OFF:DTB_OFF + 0x2ca1]
    (HERE / 'dtb_x-h2_5.33.dtb').write_bytes(blob)
    nodes, total = parse(blob)
    lines = [f'DTB @ DAT 0x{DTB_OFF:x}, totalsize={total} (0x{total:x}), записан в dtb_x-h2_5.33.dtb']
    cur = None
    for kind, path, payload in nodes:
        if kind == 'node':
            lines.append(f'/ {path}'.rstrip('/') + ' {')
        else:
            nm, ln, val = payload
            lines.append(f'    {nm} = {printable(val)}')
    (HERE / 'DTB_дерево.txt').write_text('\n'.join(lines) + '\n', encoding='utf-8')

    # поиск целевых адресов в дереве
    hits = []
    for kind, path, payload in nodes:
        if kind != 'prop':
            continue
        nm, ln, val = payload
        for pat, label in ((b'\xff\x97\x00\x00', '0xFF970000 BE'),
                           (b'\x00\x00\x97\xff', '0xFF970000 LE'),
                           (b'\xff\x90\xc3\x00', '0xFF90C300 BE'),
                           (b'\xff\x90\xe1\x00', '0xFF90E100 BE'),
                           (b'\x00\x00\x97\x00\x00\x00', 'reg-64 0x970000'),
                           (b'generic-uio', 'generic-uio'),
                           (b'movdc', 'movdc'), (b'MOVDC', 'MOVDC'), (b'uio', 'uio')):
            if pat in val:
                hits.append((path, nm, label, printable(val)[:200]))
    # поиск по всему blob
    for pat, label in ((b'movdc', 'movdc'), (b'MOVDC', 'MOVDC'), (b'0xff970000', '0xff970000-ascii'),
                       (b'0xff90c300', '0xff90c300-ascii'), (b'0xff90e100', '0xff90e100-ascii'),
                       (b'\xff\x97\x00\x00', 'FF970000 BE32'), (b'\xff\x90\xc3', 'FF90C3 BE'),
                       (b'\xff\x90\xe1', 'FF90E1 BE'), (b'uio', 'uio'), (b'cia', 'cia')):
        s = 0
        while True:
            i = blob.find(pat, s)
            if i < 0:
                break
            hits.append(('RAW', hex(i), label, blob[max(0, i - 32):i + 48].hex(' ')))
            s = i + 1
    print('=== совпадения в DTB ===')
    for h in hits:
        print(h)
    print(f'узлов/свойств: {len(nodes)}')
    print(f'written DTB_дерево.txt ({len(lines)} строк)')

    # конфиг ядра
    try:
        d = zlib.decompressobj(31)
        cfg = d.decompress(dec[0x413b474:0x413b474 + (1 << 20)])
        (HERE / 'ядро_конфиг.txt').write_bytes(cfg)
        print('ядро_конфиг.txt:', len(cfg), 'байт')
    except Exception as exc:  # noqa: BLE001
        print('config error', exc)

    # сравнение DTB и конфига 5.30 vs 5.33
    deco = DAT_OLD.read_bytes().translate(TRANS)
    for label, off, ln in (('DTB', DTB_OFF, 0x2ca1), ('ikcfg', 0x413b474, 14209),
                           ('kernel-head-64K', 0x3cb0274, 0x10000)):
        a = dec[off:off + ln]
        b = deco[off:off + ln]
        import hashlib
        print(f'{label}: 5.33={hashlib.sha256(a).hexdigest()[:16]} 5.30={hashlib.sha256(b).hexdigest()[:16]} '
              f'равны={a == b} различий={sum(1 for x, y in zip(a, b) if x != y)}')


if __name__ == '__main__':
    main()
