"""24: быстрая сверка: та же векторная таблица (SP=0xA00, reset=0xA01) по смещению 0x1C0274
в DAT X-H2S и X-T5. Только чтение; ничего не пишет, кроме otчётного json.
"""
import hashlib
import json
import struct
import sys
from pathlib import Path

HERE = Path(__file__).resolve().parent
sys.path.insert(0, str(HERE))
import m4lib

DATS = {
    'X-H2 5.33': m4lib.DAT_NEW,
    'X-H2S 7.31': Path(r'<корень проекта>\Firmware на прочиеFuji\FWUP0027(new).DAT'),
    'X-T5 4.32': Path(r'<корень проекта>\Firmware на прочиеFuji\FWUP0030(new).DAT'),
}
out = {}
for name, path in DATS.items():
    raw = Path(path).read_bytes()
    dec = raw.translate(m4lib.TRANSLATION)
    sp, reset = struct.unpack_from('<2I', dec, 0x1C0274)
    print(f'{name}: {path.name} size={len(raw):#x}; @0x1C0274 SP={sp:#x} reset={reset:#x}')
    row = {'sp': hex(sp), 'reset': hex(reset)}
    if reset == 0xA01:
        # найти конец образа: идём вперёд до выравнивания 0x1000, где начинаются нули/другое
        for size in (0x31A80, 0x22900, 0x32470):
            cand = dec[0x1C0274:0x1C0274 + size]
            print(f'   срез {size:#x}: sha256={hashlib.sha256(cand).hexdigest()[:16]} '
                  f'хвост={cand[-8:].hex()}')
            row[f'slice_{size:#x}'] = hashlib.sha256(cand).hexdigest()[:16]
    out[name] = row
(HERE / 'сверка_моделей.json').write_text(json.dumps(out, ensure_ascii=False, indent=1), encoding='utf8')
print('saved сверка_моделей.json')
