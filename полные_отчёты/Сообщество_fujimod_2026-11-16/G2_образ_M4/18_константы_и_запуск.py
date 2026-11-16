"""18: полная перепись абсолютных констант образа M4 + проверка MOVDC + код запуска на A53.

(а) свип образа M4, извлечение литералов и пар movw/movt → гистограмма страниц, полный
    список констант в 0x5F9xxxxx/0xFF9xxxxx/0x100xxxxx/0xFA2xxxxx;
(б) точный поиск 0x10030001 / 0x10030000 / 0xFF970000 / 0x5F970000 по DAT и блокам
    (только 4-байтное выравнивание — литералы и таблицы);
(в) дизасм блока 0 вокруг ссылок на 0x1C0274 и 0xFF90C928 (путь запуска M4);
(г) дамп строк образа около 0x2DD00..0x2DF80.

Только чтение.
"""
import json
import re
import struct
import sys
from collections import Counter, defaultdict
from pathlib import Path

from capstone import Cs, CS_ARCH_ARM, CS_MODE_THUMB, CS_MODE_MCLASS, CS_ARCH_ARM64, CS_MODE_LITTLE_ENDIAN

HERE = Path(__file__).resolve().parent
sys.path.insert(0, str(HERE))
import m4lib

IMG_OFF, IMG_LEN = 0x1C0274, 0x31A80
fw = m4lib.load_dat(m4lib.DAT_NEW)
dec = fw['dec']
img = dec[IMG_OFF:IMG_OFF + IMG_LEN]
blocks = [m4lib.load_block('X-H2', 'new', i) for i in range(4)]
cs = Cs(CS_ARCH_ARM, CS_MODE_THUMB | CS_MODE_MCLASS)
cs64 = Cs(CS_ARCH_ARM64, CS_MODE_LITTLE_ENDIAN)
out = {}


def sweep(data):
    res, off, n = [], 0, len(data)
    while off < n - 1:
        got = False
        for x in cs.disasm(data[off:off + 16], off):
            res.append(x)
            off += x.size
            got = True
            break
        if not got:
            off += 2
    return res


ins = sweep(img)
print(f'свип: {len(ins)} инструкций')

consts = []      # (value, insn_addr, kind)
movw = {}
for x in ins:
    ops = [p.strip() for p in x.op_str.split(',')]
    if x.mnemonic == 'movw' and len(ops) == 2 and ops[1].startswith('#'):
        movw[ops[0]] = (int(ops[1][1:], 0), x.address)
    elif x.mnemonic == 'movt' and len(ops) == 2 and ops[0] in movw and ops[1].startswith('#'):
        lo, a0 = movw.pop(ops[0])
        consts.append((int(ops[1][1:], 0) << 16 | lo, a0, 'movw/movt'))
    elif x.mnemonic.startswith('ldr'):
        m = re.search(r'\[pc, #(0x[0-9a-f]+|\d+)\]', x.op_str)
        if m:
            tgt = ((x.address + 4) & ~3) + int(m.group(1), 0)
            if 0 <= tgt <= len(img) - 4:
                consts.append((struct.unpack_from('<I', img, tgt)[0], x.address, 'literal'))
print(f'констант извлечено: {len(consts)} (литералы+movw/movt)')

PER = defaultdict(Counter)
for v, a, kind in consts:
    if 0x5F000000 <= v < 0x60000000:
        PER['0x5F9x (алиас периферии)'][v & 0xFFFFF000] += 1
    elif 0xFF000000 <= v < 0x100000000:
        PER['0xFFxxxxxx'][v & 0xFFFFF000] += 1
    elif 0x10000000 <= v < 0x10100000:
        PER['0x100xxxxx'][v] += 1
    elif 0xFA000000 <= v < 0xFB000000:
        PER['0xFAxxxxxx'][v & 0xFFFFF000] += 1
    elif 0xF0000000 <= v < 0xF8000000:
        PER['flash'][v & 0xFFFFF000] += 1
for grp, c in PER.items():
    print(f'\n  {grp}:')
    for page, n in sorted(c.items()):
        print(f'    {page:#010x}  x{n}')
out['page_hist'] = {g: {hex(p): n for p, n in c.items()} for g, c in PER.items()}
out['constants'] = [{'value': hex(v), 'insn': hex(a), 'kind': k} for v, a, k in consts]

print('\n== (б) точный поиск MOVDC-констант (4-байтное выравнивание)')
TARGETS = {'0x10030001': 0x10030001, '0x10030000': 0x10030000, '0xFF970000': 0xFF970000,
           '0x5F970000': 0x5F970000, '0xFF9700D8': 0xFF9700D8, '0x5F9700D8': 0x5F9700D8}
res = {}
for name, v in TARGETS.items():
    row = {}
    pat = struct.pack('<I', v)
    import numpy as np
    a = np.frombuffer(dec[:len(dec) & ~3], dtype='<u4')
    hits = np.nonzero(a == v)[0]
    if len(hits):
        row['DAT'] = [hex(int(h) * 4) for h in hits[:10]]
    for i, b in enumerate(blocks):
        bb = np.frombuffer(b.data[:len(b.data) & ~3], dtype='<u4')
        hh = np.nonzero(bb == v)[0]
        if len(hh):
            row[f'block{i}'] = [hex(b.base + int(h) * 4) for h in hh[:10]]
    res[name] = row
    print(f'  {name}: {row if row else "нет"}' + ('' if not row else f' (всего {len(hits)})'))
out['movdc_consts'] = res

print('\n== (в) блок 0: контекст 0x1C0274 (VA 0x199d23c) и 0xFF90C928 (VA 0x18eb6d8)')
b0 = blocks[0]


def dis64(b, va, count=18, before=8):
    start = va - before * 4
    print(f'--- VA {va:#x} (DAT-смещение внутри блока {b.off(va):#x})')
    for x in cs64.disasm(b.data[b.off(start):b.off(start) + count * 4], start):
        mark = '  <== ' if va - 4 <= x.address <= va + 4 else ''
        print(f'  {x.address:08x}  {x.mnemonic:<8} {x.op_str}{mark}')


dis64(b0, 0x199D23C)
dis64(b0, 0x18EB6D8)

print('\n== (г) строки образа около 0x2DD00..0x2DF80')
seg = img[0x2DD00:0x2DF80]
for i in range(0, len(seg), 16):
    ch = seg[i:i + 16]
    print(f'  {IMG_OFF + 0x2DD00 + i:08x}  {ch.hex(" "):<47}  ' +
          ''.join(chr(c) if 32 <= c < 127 else '.' for c in ch))
out['strings_seg'] = seg.hex()

(HERE / 'константы_и_запуск.json').write_text(json.dumps(out, ensure_ascii=False, indent=1), encoding='utf8')
print('saved константы_и_запуск.json')
