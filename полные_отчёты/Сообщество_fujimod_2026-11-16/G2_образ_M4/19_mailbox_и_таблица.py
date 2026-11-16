"""19: протокол mailbox в образе M4 и таблица диспетчеризации команд.

(а) дизасм кода вокруг литералов mailbox (0x5F90E100/10C/114/120) — как читаются/пишутся
    регистры, что за структура сообщения;
(б) разбор таблицы по смещению 0x2DE90 (12-байтные записи {id, handler, aux}) — это похоже
    на таблицу обработчиков команд; печатаем записи и первые инструкции каждого обработчика;
(в) дизасм кода DMA/flash-DMA (0x5F930000/0x5F939000) — куда M4 перемещает данные;
(г) имена потоков ThreadX и ближайшие строки.

Только чтение.
"""
import json
import struct
import sys
from pathlib import Path

from capstone import Cs, CS_ARCH_ARM, CS_MODE_THUMB, CS_MODE_MCLASS

HERE = Path(__file__).resolve().parent
sys.path.insert(0, str(HERE))
import m4lib

IMG_OFF, IMG_LEN = 0x1C0274, 0x31A80
fw = m4lib.load_dat(m4lib.DAT_NEW)
img = fw['dec'][IMG_OFF:IMG_OFF + IMG_LEN]
cs = Cs(CS_ARCH_ARM, CS_MODE_THUMB | CS_MODE_MCLASS)
out = {}


def sweep(data, start=0, end=None):
    res, off, n = [], start, (len(data) if end is None else end)
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
by_addr = {x.address: x for x in ins}


def dump(lo, hi, tag='', limit=120):
    print(f'--- {tag} [{lo:#x}..{hi:#x})  DAT {IMG_OFF + lo:#x}')
    n = 0
    for x in ins:
        if lo <= x.address < hi:
            print(f'  {x.address:06x}  {x.bytes.hex():<10} {x.mnemonic:<8} {x.op_str}')
            n += 1
            if n >= limit:
                break


print('== (а) код работы с mailbox')
for lo, hi, tag in ((0x2F60, 0x3060, 'mailbox A (0x2F60)'),
                    (0x3130, 0x31E0, 'mailbox B (0x3130)'),
                    (0x3270, 0x3320, 'mailbox C (0x3270)'),
                    (0x3670, 0x37A0, 'mailbox D (0x3670)')):
    dump(lo, hi, tag)

print('\n== (б) таблица записей по 12 байт с 0x2DE90')
table = []
off = 0x2DE90
while off + 12 <= IMG_LEN:
    a, b, c = struct.unpack_from('<3I', img, off)
    if a == 0 and b == 0 and c == 0:
        break
    if a > 0x10000 or b > IMG_LEN * 2:
        break
    table.append({'entry_off': hex(off), 'id': hex(a), 'handler': hex(b), 'aux': hex(c)})
    off += 12
print(f'  записей: {len(table)}')
for row in table[:40]:
    print(f"   {row['entry_off']:>8}  id={row['id']:>8} handler={row['handler']:>8} aux={row['aux']}")
out['dispatch_table'] = table

print('\n== первые инструкции обработчиков (первые 8 записей)')
for row in table[:8]:
    h = int(row['handler'], 16) & ~1
    dump(h, h + 24, f"handler id={row['id']}", limit=12)

print('\n== (в) код DMA / flash-DMA')
for lo, hi, tag in ((0x1F580, 0x1F620, 'DMA regs 0x5F9300xx'),
                    (0x1FB70, 0x1FC20, 'flash-DMA 0x5F9390xx'),
                    (0x20D30, 0x20DA0, '0x5F90C700')):
    dump(lo, hi, tag)

print('\n== (г) строки/имена потоков ThreadX (образ 0x2DD00..0x2E400)')
seg = img[0x2DD00:0x2E400]
import re
for m in re.finditer(rb'[\x20-\x7e]{4,}', seg):
    print(f'  +{0x2DD00 + m.start():#07x}  {m.group().decode("latin1")}')
out['threadx_area_strings'] = [(hex(0x2DD00 + m.start()), m.group().decode('latin1'))
                               for m in re.finditer(rb'[\x20-\x7e]{4,}', seg)]

(HERE / 'mailbox_и_таблица.json').write_text(json.dumps(out, ensure_ascii=False, indent=1), encoding='utf8')
print('saved mailbox_и_таблица.json')
