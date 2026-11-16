"""Инвентаризация сырых областей DAT: ARM64 Image, DTB, ELF, CPIO, gzip/XZ.

Только чтение DAT. Ничего не извлекает наружу, кроме отчёта в своей папке.
"""
from pathlib import Path
import gzip
import io
import lzma
import struct
import zlib

HERE = Path(__file__).resolve().parent
DAT_NEW = Path(r'<корень проекта>\FIRMWARE\ver new\FWUP0028 (2).DAT')
DAT_OLD = Path(r'<корень проекта>\FIRMWARE\ver 5.30\FWUP0028.DAT')
OUT = HERE / 'DAT_сырые_области.txt'

TRANS = bytes.maketrans(bytes(range(256)), bytes(255 - i for i in range(256)))

REGIONS_NEW = [(0x0, 0x300274, 'заголовок DAT'),
               (0x284375c, 0x6931508, 'после блока 3 (Linux/rootfs)'),
               (0x1690dab, 0x24a0274, 'между блоком 2 и блоком 3')]


def cstr(d, off, limit=400):
    raw = d[off:off + limit].split(b'\0', 1)[0]
    return raw.decode('utf-8', 'replace')


def dtb_info(dec, off, out):
    magic, totalsize, off_struct, off_strings, off_rsv, version, last_comp, boot_cpuid, size_strings, size_struct = \
        struct.unpack_from('>10I', dec, off)
    out.append(f'  DTB @ 0x{off:x}: totalsize={totalsize} (0x{totalsize:x}) ver={version} '
               f'struct=0x{off_struct:x} strings=0x{off_strings:x} size_strings={size_strings}')
    blob = dec[off:off + totalsize]
    # model / compatible / bootargs
    for key in (b'model\0', b'compatible\0', b'bootargs\0', b'stdout-path\0', b'memory\0'):
        i = blob.find(key)
        out.append(f'    "{key.decode(errors="replace").strip(chr(0))}" -> {i if i < 0 else hex(off+i)}')
    # все строки с console/bootargs
    for pat in (b'bootargs', b'console=', b'root=', b'init=', b''
                                                             b'fujifilm', b'xh2', b'X-H2'):
        s = blob.find(pat)
        if s >= 0:
            out.append(f'    содержит {pat!r} @ 0x{off+s:x}: {blob[s-40:s+120]!r}')
    # список строк из блока strings
    strings = blob[off_strings:off_strings + size_strings]
    names = [x for x in strings.split(b'\0') if x]
    out.append(f'    строк в strings-блоке: {len(names)}; первые 40: {[x.decode("latin1") for x in names[:40]]}')


def arm64_image(dec, off, out):
    if dec[off + 0x38:off + 0x3c] != b'ARM\x64':
        out.append(f'  нет ARM64 Image magic по 0x{off+0x38:x}')
        return
    code0, code1, text_offset, image_size, flags, res2, res3, res4, magic = \
        struct.unpack_from('<4I4Q4I', dec, off - 0) if False else (None,) * 9
    code0, code1 = struct.unpack_from('<2I', dec, off)
    text_offset, image_size, flags = struct.unpack_from('<3Q', dec, off + 8)
    out.append(f'  ARM64 Image @ 0x{off:x}: code0={code0:#x} code1={code1:#x} '
               f'text_offset=0x{text_offset:x} image_size=0x{image_size:x} ({image_size}) flags=0x{flags:x}')
    out.append(f'    баннер: {cstr(dec, off + 0x300, 200)!r}')


def elf_info(dec, off, out):
    if dec[off:off + 4] != b'\x7fELF':
        return
    e_ident = dec[off:off + 16]
    e_type, e_machine, e_version, e_entry, e_phoff, e_shoff, e_flags, e_ehsize, \
        e_phentsize, e_phnum, e_shentsize, e_shnum, e_shstrndx = struct.unpack_from('<HHIQQQIHHHHHH', dec, off + 16)
    out.append(f'  ELF @ 0x{off:x}: class={e_ident[4]} data={e_ident[5]} type={e_type} machine={e_machine} '
               f'entry=0x{e_entry:x} phoff=0x{e_phoff:x} phnum={e_phnum} shoff=0x{e_shoff:x} shnum={e_shnum}')
    for k in range(min(e_phnum, 20)):
        p = off + e_phoff + k * e_phentsize
        if p + 56 > len(dec):
            break
        p_type, p_flags, p_offset, p_vaddr, p_paddr, p_filesz, p_memsz, p_align = \
            struct.unpack_from('<IIQQQQQQ', dec, p)
        out.append(f'    ph[{k}] type={p_type} flags={p_flags} off=0x{p_offset:x} vaddr=0x{p_vaddr:x} '
                   f'filesz=0x{p_filesz:x} memsz=0x{p_memsz:x} align=0x{p_align:x}')
    # section headers
    for k in range(min(e_shnum, 30)):
        s = off + e_shoff + k * e_shentsize
        if s + 64 > len(dec):
            break
        sh_name, sh_type, sh_flags, sh_addr, sh_offset, sh_size, sh_link, sh_info, sh_addralign, sh_entsize = \
            struct.unpack_from('<IIQQQQIIQQ', dec, s)
        out.append(f'    sh[{k}] name=0x{sh_name:x} type={sh_type} flags=0x{sh_flags:x} addr=0x{sh_addr:x} '
                   f'off=0x{sh_offset:x} size=0x{sh_size:x}')


def gzip_at(dec, off, out, name, maxout=64 << 20):
    try:
        d = zlib.decompressobj(31)
        data = d.decompress(dec[off:off + (maxout)], maxout)
        out.append(f'  gzip @ 0x{off:x} ({name}): распаковано {len(data)} байт, '
                   f'использовано {len(dec[off:])-len(d.unused_data)}')
        out.append(f'    первые 200: {data[:200]!r}')
        return data
    except Exception as exc:  # noqa: BLE001
        out.append(f'  gzip @ 0x{off:x} ({name}): ошибка {exc}')
        return None


def xz_at(dec, off, out, maxout=64 << 20):
    try:
        d = lzma.LZMADecompressor(format=lzma.FORMAT_XZ)
        data = d.decompress(dec[off:off + maxout], maxout)
        out.append(f'  XZ @ 0x{off:x}: распаковано {len(data)} байт; первые 200: {data[:200]!r}')
        return data
    except Exception as exc:  # noqa: BLE001
        out.append(f'  XZ @ 0x{off:x}: ошибка {exc}')
        return None


def cpio_list(dec, off, out, maxfiles=80):
    pos = off
    files = []
    total = 0
    while True:
        hdr = dec[pos:pos + 110]
        if not hdr or hdr[:6] not in (b'070701', b'070702'):
            break
        try:
            fields = [int(hdr[6 + i * 8:14 + i * 8], 16) for i in range(13)]
        except ValueError:
            break
        ino, mode, uid, gid, nlink, mtime, filesize, devmaj, devmin, rdevmaj, rdevmin, namesize, check = fields
        name = dec[pos + 110:pos + 110 + namesize - 1].decode('latin1')
        hdr_len = 110 + namesize
        hdr_len = (hdr_len + 3) & ~3
        data_off = pos + hdr_len
        files.append((name, filesize, mode, data_off))
        total += filesize
        pos = data_off + ((filesize + 3) & ~3)
        if name == 'TRAILER!!!':
            break
        if len(files) > 200000:
            break
    out.append(f'  CPIO @ 0x{off:x}: файлов {len(files)}, суммарный размер данных {total} (0x{total:x}), '
               f'конец 0x{pos:x}')
    for name, size, mode, doff in files[:maxfiles]:
        kind = 'd' if (mode & 0o170000) == 0o040000 else ('l' if (mode & 0o170000) == 0o120000 else 'f')
        out.append(f'    {kind} {size:>9} 0x{doff:08x}  {name}')
    if len(files) > maxfiles:
        out.append(f'    ... ещё {len(files)-maxfiles}')
    return files


def main():
    out = []
    for label, dat in (('5.33', DAT_NEW), ('5.30', DAT_OLD)):
        raw = dat.read_bytes()
        dec = raw.translate(TRANS)
        out.append(f'##### DAT {label} #####')
        if label == '5.33':
            for a, z, nm in REGIONS_NEW:
                out.append(f'--- область 0x{a:x}..0x{z:x} ({nm}), len=0x{z-a:x} ---')
                arm64_image(dec, 0x3cb0274, out)
                dtb_info(dec, 0x3c40274, out)
                elf_info(dec, 0x4137274, out)
                gzip_at(dec, 0x413b474, out, 'IKCFG (конфиг ядра)')
                gzip_at(dec, 0x42dfdcc, out, 'второй gzip')
                xz_at(dec, 0x4240e94, out)
                cpio_list(dec, 0x4225334, out)
        # хеши областей для сравнения версий
        for a, z, nm in REGIONS_NEW:
            import hashlib
            out.append(f'  sha256 0x{a:x}..0x{z:x} ({nm}) = {hashlib.sha256(dec[a:z]).hexdigest()}')
        out.append('')
    OUT.write_text('\n'.join(out) + '\n', encoding='utf-8')
    print('written', OUT)


if __name__ == '__main__':
    main()
