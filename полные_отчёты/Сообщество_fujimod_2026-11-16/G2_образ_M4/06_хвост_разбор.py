"""06: что лежит в хвосте DAT (68 МиБ после блока 3) — ELF, DTB, cpio, xz.

Скрипт разбирает найденные сигнатуры: заголовок ELF (машина/класс/точка входа,
имена секций при наличии), FDT (model/compatible — определяет SoC), cpio newc, xz.
Печатает hex+ASCII вокруг границ и строки, похожие на имена образов (m4, cm4, dtcm).
Только чтение.
"""
import json
import struct
import sys
from pathlib import Path

HERE = Path(__file__).resolve().parent
sys.path.insert(0, str(HERE))
import m4lib

fw = m4lib.load_dat(m4lib.DAT_NEW)
dec = fw['dec']
out = {}


def dump(off, n=0x60, tag=''):
    b = dec[off:off + n]
    print(f'--- {tag} @ {off:#x}')
    for i in range(0, len(b), 16):
        chunk = b[i:i + 16]
        asc = ''.join(chr(c) if 32 <= c < 127 else '.' for c in chunk)
        print(f'  {off + i:08x}  {chunk.hex(" "):<47}  {asc}')


def parse_elf(off):
    h = dec[off:off + 64]
    cls, data, ver, osabi = h[4], h[5], h[6], h[7]
    etype, machine, version, entry = struct.unpack_from('<HHIQ', h, 16)
    phoff, shoff = struct.unpack_from('<QQ', h, 32)
    ehsize, phentsize, phnum, shentsize, shnum, shstrndx = struct.unpack_from('<HHHHHH', h, 52)
    r = {'off': hex(off), 'class': cls, 'data': data, 'type': etype, 'machine': machine,
         'entry': hex(entry), 'phoff': hex(phoff), 'phnum': phnum, 'shoff': hex(shoff),
         'shnum': shnum, 'shstrndx': shstrndx}
    names = []
    if shnum and shstrndx < shnum:
        stroff = struct.unpack_from('<Q', dec, off + shoff + shstrndx * shentsize + 24)[0]
        for i in range(min(shnum, 64)):
            nm = struct.unpack_from('<I', dec, off + shoff + i * shentsize)[0]
            if nm == 0:
                continue
            s = dec[off + stroff + nm:off + stroff + nm + 64].split(b'\0')[0]
            names.append(s.decode('latin1', 'replace'))
    r['sections'] = names
    return r


def parse_fdt(off):
    magic, size, off_struct, off_strings = struct.unpack_from('>4I', dec, off)
    r = {'off': hex(off), 'size': size, 'struct': hex(off_struct), 'strings': hex(off_strings)}
    strs = []
    p = off + off_strings
    end = off + size
    while p < end:
        q = dec.find(b'\0', p)
        if q < 0:
            break
        s = dec[p:q]
        if s:
            strs.append(s.decode('latin1', 'replace'))
        p = q + 1
    r['strings_sample'] = strs[:120]
    r['model'] = [s for s in strs if s.startswith('Fujifilm') or s.lower().startswith('model') or s.startswith('X-')][:10]
    r['compatible'] = [s for s in strs if s.startswith(('fsl,', 'arm,', 'fujifilm', 'simple-bus'))][:40]
    return r


for off, tag in ((0x284375c, 'начало хвоста'), (0x293375c, 'хвост: 0x00/0xFF'),
                 (0x297375c, 'хвост: начало содержимого'), (0x298375c, 'хвост: текст')):
    dump(off, 0x60, tag)

# ELF
elf = parse_elf(0x4137274)
print('ELF:', json.dumps({k: v for k, v in elf.items() if k != 'sections'}, ensure_ascii=False))
print('  секции:', elf['sections'][:40])
dump(0x4137274, 0x40, 'ELF header')
out['elf'] = elf

# DTB
dtb = parse_fdt(0x3c40274)
print('DTB:', {k: dtb[k] for k in ('off', 'size')})
print('  model:', dtb['model'])
print('  compatible:', dtb['compatible'])
print('  строки:', dtb['strings_sample'][:60])
dump(0x3c40274, 0x40, 'DTB header')
out['dtb'] = dtb

# cpio newc
dump(0x4225334, 0x80, 'cpio')
dump(0x4240e94, 0x40, 'xz')
dump(0x413b474, 0x40, 'gzip после ELF')

# ищем имена образов/разделов в хвосте
import re
for pat in (rb'[ -~]{6,}',):
    pass
tail = dec[0x284375c:]
kw = re.compile(rb'(?i)(m4|cortex|cm4|itcm|dtcm|companion|freertos|partition|firmware|kernel|initramfs|rootfs|dtb)')
hits = []
for m in kw.finditer(tail):
    s = tail[max(0, m.start() - 40):m.start() + 60]
    if b'\0' in s and all(32 <= c < 127 or c == 0 for c in s):
        hits.append((0x284375c + m.start(), s.decode('latin1')))
    if len(hits) >= 60:
        break
print(f'\nстроки с ключевыми словами в хвосте: {len(hits)}')
for off, s in hits[:40]:
    print(f'  {off:#x}: {s!r}')
out['tail_keyword_strings'] = [{'off': hex(o), 's': s} for o, s in hits]

(HERE / 'хвост_разбор.json').write_text(json.dumps(out, ensure_ascii=False, indent=1), encoding='utf8')
print('saved хвост_разбор.json')
