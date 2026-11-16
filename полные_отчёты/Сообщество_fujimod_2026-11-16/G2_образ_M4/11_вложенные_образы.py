"""11: (а) вложенные сжатые образы в блоках 0-3 (gzip/zlib/zstd/lz4) с попыткой распаковки
и проверкой результата на таблицу векторов/Thumb-код;
(б) ADRP на страницы flash-апертуры 0xF0000000 и MOVDC 0xFF970000 в блоках 0-2;
(в) строки-ключи (Cortex-M, CM4, companion, mailbox, FreeRTOS, HardFault...) в блоках и префиксе.

Только чтение.
"""
import json
import re
import struct
import sys
import zlib
from pathlib import Path

import numpy as np

HERE = Path(__file__).resolve().parent
sys.path.insert(0, str(HERE))
import m4lib

sys.path.insert(0, str(m4lib.ANALYSIS / 'Сравнение_версий_2026-11-16'))
import fwcommon

fw = m4lib.load_dat(m4lib.DAT_NEW)
dec = fw['dec']
blocks = [m4lib.load_block('X-H2', 'new', i) for i in range(4)]
out = {}

print('== (а) сжатые потоки внутри распакованных блоков')
streams = []
for i, b in enumerate(blocks):
    data = b.data
    cands = []
    for sig, wbits, name in ((b'\x1f\x8b\x08', 16 + zlib.MAX_WBITS, 'gzip'),
                             (b'\x78\x9c', zlib.MAX_WBITS, 'zlib9c'),
                             (b'\x78\xda', zlib.MAX_WBITS, 'zlibda'),
                             (b'\x78\x01', zlib.MAX_WBITS, 'zlib01')):
        pos = 0
        while len(cands) < 400:
            j = data.find(sig, pos)
            if j < 0:
                break
            cands.append((j, wbits, name))
            pos = j + 1
    ok = 0
    for j, wbits, name in cands:
        try:
            d = zlib.decompressobj(wbits)
            outb = d.decompress(data[j:j + 8_000_000], 16_000_000)
        except Exception:
            continue
        if len(outb) < 0x4000:
            continue
        ok += 1
        m = m4lib.thumb_metrics_np(outb, 0, min(len(outb), 0x40000))
        vec = []
        import array
        a = array.array('I')
        a.frombytes(bytes(outb[:len(outb) & ~3]))
        sp = a[0] if a else 0
        streams.append({'block': i, 'off': hex(b.base + j), 'fmt': name,
                        'in_avail': len(data) - j, 'out_len': len(outb),
                        'first16': outb[:16].hex(),
                        'sp_word': hex(sp), 'thumb': m,
                        'printable': sum(32 <= c < 127 for c in outb[:4096]) / 4096})
        if ok <= 8:
            print(f"  block{i} {name} @ {b.base + j:#x}: -> {len(outb):#x} байт, "
                  f"первые {outb[:16].hex()}, Thumb bl={m.get('bl')} bx_lr={m.get('bx_lr')}")
    print(f'  блок {i}: кандидатов {len(cands)}, успешно распаковано {ok}')
out['streams'] = streams

print('\n== (б) ADRP на flash-апертуру 0xF0000000 и MOVDC 0xFF970000 (блоки 0-2)')
adrp = {}
for idx in (0, 1, 2):
    b = blocks[idx]
    for page in (0xF0000000, 0xFF970000, 0xFF980000, 0xFF900000):
        sites = fwcommon.adrp_sites(b, page)
        if sites:
            adrp[f'block{idx}@{page:#x}'] = [hex(s) for s, _ in sites[:12]]
            print(f'  block{idx} {page:#x}: {len(sites)} сайтов {[hex(s) for s, _ in sites[:6]]}')
if not adrp:
    print('  ADRP на эти страницы не найдено ни в одном блоке')
out['adrp_pages'] = adrp

print('\n== (в) строки-ключи')
KW = [b'Cortex-M', b'Cortex M', b'CM4', b'cortex-m4', b'companion', b'Companion', b'mailbox',
      b'Mailbox', b'FreeRTOS', b'freertos', b'HardFault', b'hardfault', b'NVIC', b'SysTick',
      b'ITCM', b'DTCM', b'ARMv7-M', b'armv7-m', b'remoteproc', b'rproc', b'M4', b'm4']
res = {}
for name, buf in [('prefix', dec[:0x300274])] + [(f'block{i}', b.data) for i, b in enumerate(blocks)] + \
                 [('raw_tail', dec[0x284375c:])]:
    row = {}
    for k in KW:
        c = buf.count(k)
        if c:
            row[k.decode()] = c
    res[name] = row
    print(f'  {name}: {row}')
out['keywords'] = {k: v for k, v in res.items()}

# контекст самых интересных совпадений M4/CM4/companion
print('\n== контекст совпадений (M4, CM4, companion, Cortex-M)')
for name, buf in [('prefix', dec[:0x300274])] + [(f'block{i}', b.data) for i, b in enumerate(blocks)] + \
                 [('raw_tail', dec[0x284375c:])]:
    for k in (b'M4', b'CM4', b'companion', b'Cortex-M'):
        pos = 0
        shown = 0
        while shown < 5:
            j = buf.find(k, pos)
            if j < 0:
                break
            lo, hi = max(0, j - 48), min(len(buf), j + 48)
            ctx = buf[lo:hi]
            asc = ''.join(chr(c) if 32 <= c < 127 else '.' for c in ctx)
            print(f'  {name} {k.decode():10s} @ {lo:#x}: {asc!r}')
            pos, shown = j + 1, shown + 1
out['keyword_context'] = 'напечатано выше'

(HERE / 'вложенные_образы.json').write_text(json.dumps(out, ensure_ascii=False, indent=1), encoding='utf8')
print('saved вложенные_образы.json')
