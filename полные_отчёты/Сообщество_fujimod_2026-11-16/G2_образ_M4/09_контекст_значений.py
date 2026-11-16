"""09: где именно встречаются точные значения 0xFA200000 / 0xFA300000 / 0xFF91C00C /
0xFF970000 и что вокруг них. Для блоков дополнительно дизассемблируется ARM64-контекст
(если значение — часть MOVZ/MOVK-пары или литерала в таблице). Только чтение.
"""
import json
import struct
import sys
from pathlib import Path

HERE = Path(__file__).resolve().parent
sys.path.insert(0, str(HERE))
import m4lib

sys.path.insert(0, str(m4lib.ANALYSIS / 'Сравнение_версий_2026-11-16'))
import fwcommon

fw = m4lib.load_dat(m4lib.DAT_NEW)
dec = fw['dec']
blocks = [m4lib.load_block('X-H2', 'new', i) for i in range(4)]
out = {}


def ctx(buf, i, base=0, n=48):
    lo, hi = max(0, i - n), min(len(buf), i + n)
    rows = []
    for k in range(lo, hi, 16):
        ch = buf[k:k + 16]
        rows.append(f'  {base + k:08x}  {ch.hex(" "):<47}  ' +
                    ''.join(chr(c) if 32 <= c < 127 else '.' for c in ch))
    return rows


def report(name, value, buffers):
    print(f'\n=== {name} = {value:#x}')
    rows = []
    for bname, data, base in buffers:
        pat = struct.pack('<I', value)
        pos = 0
        hits = []
        while True:
            i = data.find(pat, pos)
            if i < 0 or len(hits) >= 12:
                break
            hits.append(i)
            pos = i + 1
        if not hits:
            continue
        print(f'  -- {bname}: {len(hits)} (первые {len(hits)})')
        for i in hits[:6]:
            print('\n'.join(ctx(data, i, base)))
            print('   ----')
            rows.append({'buffer': bname, 'off': base + i})
    out[name] = rows


buffers = [('raw', dec, 0)] + [(f'block{i}', b.data, b.base) for i, b in enumerate(blocks)]
report('FA200000', 0xFA200000, buffers)
report('FA300000', 0xFA300000, buffers)
report('FF91C00C', 0xFF91C00C, buffers)
report('FF970000', 0xFF970000, buffers)

# для блока 1: что за инструкции вокруг 0xFF970000 (MOVZ/MOVK?)
print('\n== ARM64 вокруг 0xFF970000 в блоке 1')
b1 = blocks[1]
pat = struct.pack('<I', 0xFF970000)
pos, shown = 0, 0
while shown < 5:
    i = b1.data.find(pat, pos)
    if i < 0:
        break
    va = b1.base + i
    print(f'--- VA {va:#x}')
    print(fwcommon.dis(b1, va - 0x20, 16))
    pos, shown = i + 1, shown + 1

(HERE / 'контекст_значений.json').write_text(json.dumps(out, ensure_ascii=False, indent=1), encoding='utf8')
print('saved контекст_значений.json')
