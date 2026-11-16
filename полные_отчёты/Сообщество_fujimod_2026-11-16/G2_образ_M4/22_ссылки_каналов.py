"""22: ссылается ли A53-прошивка (префикс, блоки 0-3) на mailbox 0xFF90Exxx и companion-SRAM
0xFA2xxxxx как на адреса (выровненные 4-байтные слова) — с контекстом для каждого случая.

Только чтение.
"""
import json
import struct
import sys
from pathlib import Path

import numpy as np

HERE = Path(__file__).resolve().parent
sys.path.insert(0, str(HERE))
import m4lib

fw = m4lib.load_dat(m4lib.DAT_NEW)
dec = fw['dec']
blocks = [m4lib.load_block('X-H2', 'new', i) for i in range(4)]
out = {}

REGIONS = [('prefix', dec[:0x300274], 0)] + \
          [(f'block{i}', blocks[i].data, blocks[i].base) for i in range(4)] + \
          [('tail', dec[0x284375c:], 0x284375c)]
RANGES = {'mailbox 0xFF90E000..0xFF90F000': (0xFF90E000, 0xFF90F000),
          'companion-SRAM 0xFA200000..0xFA300000': (0xFA200000, 0xFA300000),
          'clock 0xFF90C900..0xFF90CA00': (0xFF90C900, 0xFF90CA00),
          'MOVDC 0xFF970000..0xFF974000': (0xFF970000, 0xFF974000)}

for rname, data, base in REGIONS:
    a = np.frombuffer(data[:len(data) & ~3], dtype='<u4')
    print(f'== {rname} ({len(data):#x} байт)')
    for label, (lo, hi) in RANGES.items():
        m = np.nonzero((a >= lo) & (a < hi))[0]
        print(f'   {label}: {len(m)}')
        if len(m):
            for k in m[:6]:
                va = base + int(k) * 4
                o = int(k) * 4
                ctx = data[max(0, o - 16):o + 16]
                print(f'     {va:#010x}: ' + ' '.join(f'{struct.unpack_from("<I", data, max(0, o - 16) + 4 * j)[0]:#x}'
                                                      for j in range(8)))
                out.setdefault(f'{rname}:{label}', []).append(hex(va))

(HERE / 'ссылки_каналов.json').write_text(json.dumps(out, ensure_ascii=False, indent=1), encoding='utf8')
print('saved ссылки_каналов.json')
