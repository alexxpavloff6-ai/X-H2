"""20: (а) корректный разбор таблицы диспетчеризации в образе M4 (поиск выравнивания);
(б) для каждого обработчика — какие периферийные страницы он трогает (по литералам);
(в) hex-дамп таблиц на стороне A53, где встречаются 0x1C0274 и 0xFF90C928 (путь запуска).

Только чтение.
"""
import json
import re
import struct
import sys
from collections import defaultdict
from pathlib import Path

from capstone import Cs, CS_ARCH_ARM, CS_MODE_THUMB, CS_MODE_MCLASS

HERE = Path(__file__).resolve().parent
sys.path.insert(0, str(HERE))
import m4lib

IMG_OFF, IMG_LEN = 0x1C0274, 0x31A80
fw = m4lib.load_dat(m4lib.DAT_NEW)
dec = fw['dec']
img = dec[IMG_OFF:IMG_OFF + IMG_LEN]
blocks = [m4lib.load_block('X-H2', 'new', i) for i in range(4)]
cs = Cs(CS_ARCH_ARM, CS_MODE_THUMB | CS_MODE_MCLASS)
out = {}


def sweep(data):
    res, off = [], 0
    while off < len(data) - 1:
        got = False
        for x in cs.disasm(data[off:off + 16], off):
            res.append(x); off += x.size; got = True; break
        if not got:
            off += 2
    return res


ins = sweep(img)

# ---------------------------------------------------------------- (а) таблица диспетчеризации
print('== (а) таблица в образе около 0x2DE00..0x2E000: поиск выравнивания записей по 12 байт')
best = None
for start in range(0x2DD00, 0x2DE40):
    entries, off = [], start
    while off + 12 <= IMG_LEN:
        a, b, c = struct.unpack_from('<3I', img, off)
        if not (0 < a <= 0x2000) or not (0x100 <= b < IMG_LEN) or (b & 1) == 0:
            break
        entries.append((off, a, b, c))
        off += 12
    if best is None or len(entries) > len(best[1]):
        best = (start, entries)
start, entries = best
print(f'  лучшее выравнивание: {start:#x}, записей {len(entries)}')
for off, a, b, c in entries:
    print(f'   +{off:#06x}  id={a:#06x} handler={b:#07x} aux={c:#x}')
out['dispatch'] = [{'off': hex(o), 'id': hex(a), 'handler': hex(b), 'aux': hex(c)}
                   for o, a, b, c in entries]

# ---------------------------------------------------------------- (б) периферия каждого обработчика
print('\n== (б) какие периферийные страницы использует каждый обработчик')


def literals_in(lo, hi):
    vals = []
    for x in ins:
        if lo <= x.address < hi and x.mnemonic.startswith('ldr'):
            m = re.search(r'\[pc, #(0x[0-9a-f]+|\d+)\]', x.op_str)
            if m:
                t = ((x.address + 4) & ~3) + int(m.group(1), 0)
                if 0 <= t <= IMG_LEN - 4:
                    vals.append(struct.unpack_from('<I', img, t)[0])
    return vals


def classify(v):
    if 0x5F906000 <= v < 0x5F907000:
        return 'ADC'
    if 0x5F907000 <= v < 0x5F908000:
        return 'GPIO'
    if 0x5F90B000 <= v < 0x5F90C000:
        return 'GPIO3'
    if 0x5F90C000 <= v < 0x5F90D000:
        return 'CLOCK'
    if 0x5F90E000 <= v < 0x5F90F000:
        return 'MAILBOX'
    if 0x5F928000 <= v < 0x5F929000:
        return 'CAPTURE0'
    if 0x5F930000 <= v < 0x5F931000:
        return 'DMA'
    if 0x5F939000 <= v < 0x5F93A000:
        return 'FLASH_DMA'
    if 0x5F908000 <= v < 0x5F909000:
        return 'UNK_908'
    if 0x5F909000 <= v < 0x5F90A000:
        return 'UNK_909'
    return None


rows = []
for off, a, b, c in entries:
    h = b & ~1
    nxt = [e[2] & ~1 for e in entries if (e[2] & ~1) > h]
    hi = min(nxt) if nxt else h + 0x400
    hi = min(hi, h + 0x800)
    vals = literals_in(h, hi)
    cats = defaultdict(int)
    for v in vals:
        cl = classify(v)
        if cl:
            cats[cl] += 1
    rows.append({'id': hex(a), 'handler': hex(b), 'region': [hex(h), hex(hi)],
                 'periph': dict(cats), 'n_literals': len(vals)})
    print(f'  id={a:#06x} handler={b:#07x} [{h:#06x}..{hi:#06x}) лит.={len(vals)} → {dict(cats)}')
out['handlers'] = rows

# ---------------------------------------------------------------- (в) таблицы A53
print('\n== (в) hex вокруг ссылок A53 на 0x1C0274 / 0xFF90C928')
b0 = blocks[0]
for va, tag in ((0x199D23C, '0x1C0274 в блоке 0'), (0x18EB6D8, '0xFF90C928 в блоке 0')):
    o = b0.off(va) - 0x40
    print(f'--- {tag}: VA {va:#x}, DAT внутри блока {b0.off(va):#x}')
    for i in range(0, 0x80, 16):
        ch = b0.data[o + i:o + i + 16]
        print(f'  {va - 0x40 + i:09x}  {ch.hex(" "):<47}  ' +
              ''.join(chr(c) if 32 <= c < 127 else '.' for c in ch))
print('--- префикс: 0xFF90C928 @ 0x9424 и 0x3812c, 0x1C0000/0x31A80 @ 0x1a0494')
for va in (0x9424, 0x3812C, 0x1A0494):
    o = va - 0x30
    print(f'  VA {va:#x}:')
    for i in range(0, 0x60, 16):
        ch = dec[o + i:o + i + 16]
        print(f'   {va - 0x30 + i:08x}  {ch.hex(" "):<47}  ' +
              ''.join(chr(c) if 32 <= c < 127 else '.' for c in ch))

(HERE / 'диспетчер_и_запуск.json').write_text(json.dumps(out, ensure_ascii=False, indent=1), encoding='utf8')
print('saved диспетчер_и_запуск.json')
