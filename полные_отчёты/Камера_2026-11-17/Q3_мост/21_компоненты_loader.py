# -*- coding: utf-8 -*-
"""Q3 2-й круг, шаг 21: компонентная таблица DAT X-H2 5.30 (0x1A0274/0x1A0484),
заголовок loader'а и проверка сервисных VA по mapping loader'а (VA = off - 0x20274,
т.е. file 0x60274 -> VA 0x40000, как в X-T5 4.31 streams.json)."""
import struct
import sys
from pathlib import Path

HERE = Path(__file__).resolve().parent
sys.path.insert(0, str(HERE))
from q3common import prefix, dis  # noqa: E402

p = prefix()
out = []

def dump_words(off, n, label):
    out.append(f'=== {label} @ DAT {off:#x} ===')
    for i in range(n):
        w = struct.unpack_from('<I', p.data, off + 4 * i)[0]
        out.append(f'  +{4*i:#05x} [{off+4*i:#x}]: {w:#010x} ({w})')
    out.append('')

# компонентные дескрипторы
dump_words(0x1A0274, 64, 'компонентная таблица A')
dump_words(0x1A0484, 64, 'компонентная таблица B')
# заголовок loader'а (X-T5: file 0x60274, raw)
dump_words(0x60274, 16, 'loader header @0x60274')

# сервисные VA по mapping loader'а VA = off - 0x20274  =>  off = VA + 0x20274
out.append('=== сервисы по mapping loader (off = VA + 0x20274) ===')
for name, va in (('resolver', 0x5460C), ('dispatcher', 0x4A458), ('logger', 0x57670), ('scalar', 0x50D94)):
    off = va + 0x20274
    out.append(f'--- {name} VA {va:#x} -> DAT off {off:#x} ---')
    out.append(dis(p, off, 24))
    out.append('')

text = '\n'.join(out)
(HERE / '2круг_компоненты_loader.txt').write_text(text + '\n', encoding='utf-8')
print(text[:11000])
