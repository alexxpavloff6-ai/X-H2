"""25: использует ли A53-прошивка «алиас» 0x5Fxxxxxx (как M4) — быстрая проверка по блокам
и префиксу, плюс поиск 0x5F90E1xx / 0x5F90C9xx. Только чтение.
"""
import json
import sys
from collections import Counter
from pathlib import Path

import numpy as np

HERE = Path(__file__).resolve().parent
sys.path.insert(0, str(HERE))
import m4lib

fw = m4lib.load_dat(m4lib.DAT_NEW)
dec = fw['dec']
blocks = [m4lib.load_block('X-H2', 'new', i) for i in range(4)]
out = {}

for name, data, base in [('prefix', dec[:0x300274], 0)] + \
                        [(f'block{i}', blocks[i].data, blocks[i].base) for i in range(4)]:
    a = np.frombuffer(data[:len(data) & ~3], dtype='<u4')
    m = np.nonzero((a >= 0x5F000000) & (a < 0x60000000))[0]
    print(f'{name}: слов в 0x5Fxxxxxx: {len(m)}')
    if len(m):
        pages = Counter((int(a[i]) & 0xFFFFF000) for i in m[:5000])
        print('   страницы:', [(hex(p), c) for p, c in pages.most_common(8)])
        print('   примеры:', [hex(base + int(i) * 4) for i in m[:6]])
    out[name] = {'count': len(m), 'sample': [hex(base + int(i) * 4) for i in m[:20]]}

(HERE / 'алиасы_A53.json').write_text(json.dumps(out, ensure_ascii=False, indent=1), encoding='utf8')
print('saved алиасы_A53.json')
