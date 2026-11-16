"""63: поиск дескриптора записи {u16 id=0x4C, u8, u8, u32 len=0x168} в блоках 0-2 (обе версии).

Если найдём — получим адрес payload записи 0x4C и сможем искать, кто пишет payload+0x6C
(это и есть «флаг +0x74» в структуре params: заголовок 8 байт + payload).

Ищем байтовый шаблон: 4c 00 ?? ?? 68 01 00 00  и варианты (len 0x168 = 360).
Печатаем окрестности и указатель, если он рядом.

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


def emit(s=''):
    print(s)
    lines.append(s)


for state in ('new', 'old'):
    for idx in (0, 1, 2):
        b = fwcommon.load('X-H2', state, idx)
        data = b.data
        hits = []
        for i in range(0, len(data) - 24, 4):
            if data[i] == 0x4C and data[i + 1] == 0x00 and struct.unpack_from('<I', data, i + 4)[0] == 0x168:
                hits.append(i)
        emit(f'== {b.version} block{idx}: дескрипторов {{id=0x4C, len=0x168}}: {len(hits)} '
             f'{[hex(b.base + h) for h in hits[:10]]}')
        for h in hits[:4]:
            va = b.base + h
            o = h - 0x10
            emit(f'--- {va:#x}')
            for k in range(0, 0x30, 16):
                ch = data[o + k:o + k + 16]
                vals = struct.unpack_from('<4I', data, o + k)
                emit(f'  {va - 0x10 + k:09x}  {ch.hex(" "):<47} ' +
                     ' '.join(f'{v:#010x}' for v in vals))

(HERE / 'дескриптор_записи_4c.txt').write_text('\n'.join(lines) + '\n', encoding='utf8')
print('saved дескриптор_записи_4c.txt')
