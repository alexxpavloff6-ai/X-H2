"""40: кто может передавать таблицу карты регистров: ищем указатели на неё (u32/u64) в старом
и новом блоках 1, печатаем окрестности — это может быть «таблица таблиц» для generic-движка.

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

sys.path.insert(0, str(m4lib.ANALYSIS / 'Сравнение_версий_2026-11-16'))
import fwcommon

lines = []
out = {}


def emit(s=''):
    print(s)
    lines.append(s)


for state, cands in (('old', (0x386214C, 0x3862170, 0x385E14C, 0x385E170)),
                     ('new', (0x385E14C, 0x385E170, 0x385D14C, 0x385D170))):
    b = fwcommon.load('X-H2', state, 1)
    a4 = np.frombuffer(b.data[:len(b.data) & ~3], dtype='<u4')
    a8 = np.frombuffer(b.data[:len(b.data) & ~7], dtype='<u8')
    emit(f'== X-H2 {b.version}')
    for v in cands:
        h4 = [b.base + int(i) * 4 for i in np.nonzero(a4 == v)[0]]
        h8 = [b.base + int(i) * 8 for i in np.nonzero(a8 == v)[0]]
        emit(f'  {v:#x}: u32={len(h4)} {[hex(x) for x in h4[:4]]} | u64={len(h8)} {[hex(x) for x in h8[:4]]}')
        for va in (h8 or h4)[:2]:
            o = b.off(va) - 0x20
            emit(f'   окрестности {va:#x}:')
            for k in range(0, 0x60, 16):
                ch = b.data[o + k:o + k + 16]
                vals = struct.unpack_from('<4I', b.data, o + k)
                emit(f'     {va - 0x20 + k:09x}  {ch.hex(" "):<47} ' +
                     ' '.join(f'{x:#010x}' for x in vals))
        out[f'{state}_{v:x}'] = {'u32': [hex(x) for x in h4[:10]], 'u64': [hex(x) for x in h8[:10]]}

(HERE / 'указатели_на_карту.txt').write_text('\n'.join(lines) + '\n', encoding='utf8')
(HERE / 'указатели_на_карту.json').write_text(json.dumps(out, ensure_ascii=False, indent=1), encoding='utf8')
print('saved указатели_на_карту.txt/.json')
