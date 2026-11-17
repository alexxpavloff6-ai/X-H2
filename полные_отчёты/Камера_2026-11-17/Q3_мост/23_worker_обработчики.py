# -*- coding: utf-8 -*-
"""Q3 2-й круг, шаг 23: worker резолвера 0x54354, копирование дескриптора 0x4BFD8,
обработчики запросов 0x4B9B0/0x4BBD4; поиск статического дескриптора записи 0x4C в loader."""
import struct
import sys
from pathlib import Path

HERE = Path(__file__).resolve().parent
sys.path.insert(0, str(HERE))
from q3common import loader, dis, find_bytes  # noqa: E402

L = loader()
out = []
for name, va, n in (('resolve worker 0x54354', 0x54354, 70),
                    ('desc copy 0x4BFD8', 0x4BFD8, 70),
                    ('handler 0x4B9B0', 0x4B9B0, 70),
                    ('handler 0x4BBD4', 0x4BBD4, 70)):
    out.append(f'===== {name} =====')
    out.append(dis(L, va, n))
    out.append('')

# поиск статического дескриптора {u16 id=0x4C, ... u32 size=0x158/0x168}
out.append('=== поиск u16=0x004C в loader (кандидаты дескрипторов) ===')
hits = []
for o in range(0, len(L.data) - 8, 2):
    if struct.unpack_from('<H', L.data, o)[0] == 0x4C:
        size = struct.unpack_from('<I', L.data, o + 4)[0]
        b2, b3 = L.data[o + 2], L.data[o + 3]
        if size in (0x158, 0x168, 0x15C, 0x160, 0x164, 0x16C, 0x170):
            hits.append((L.base + o, size, b2, b3))
for va, size, b2, b3 in hits:
    out.append(f'  VA {va:#x}: id=0x4C type={b2} flags={b3} size={size:#x}')
out.append(f'  всего кандидатов с правдоподобным size: {len(hits)}')

text = '\n'.join(out)
(HERE / '2круг_worker_обработчики.txt').write_text(text + '\n', encoding='utf-8')
print(text[:11000])
