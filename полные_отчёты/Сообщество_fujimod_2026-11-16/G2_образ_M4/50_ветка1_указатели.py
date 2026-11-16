"""50: ветка 1 — ищем потребителя таблицы карты регистров MOVDC через УКАЗАТЕЛИ (не ADRP).

Шаги:
 1) во всех блоках 0-3 (old 5.30 / new 5.33) ищем u32/u64, равные адресам таблицы 0x385E14C/0x385E170
    и её записей (0x385E14C + k*0x18), а также «старому» варианту 0x386214C/0x3862170;
 2) ищем любые указатели в диапазон 0x385E000..0x385E400 (начало таблицы/её окно);
 3) для каждого попадания печатаем окрестности (возможный массив {base, irq, ...}).

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


def hexdump(b, va, before=0x20, after=0x40):
    o = b.off(va) - before
    for k in range(0, before + after, 16):
        ch = b.data[o + k:o + k + 16]
        vals = struct.unpack_from('<4I', b.data, o + k)
        emit(f'    {va - before + k:09x}  {ch.hex(" "):<47} ' + ' '.join(f'{v:#010x}' for v in vals))


# ---------------------------------------------------------------- (1)/(2) указатели
NEW_TABLE = [0x385E14C + 0x18 * k for k in range(10)]
OLD_TABLE = [0x386214C + 0x18 * k for k in range(10)]

for state in ('old', 'new'):
    for idx in (0, 1, 2, 3):
        b = fwcommon.load('X-H2', state, idx)
        a4 = np.frombuffer(b.data[:len(b.data) & ~3], dtype='<u4')
        a8 = np.frombuffer(b.data[:len(b.data) & ~7], dtype='<u8')
        # 2) все указатели в окно таблицы
        window = (0x385E000, 0x385E400) if state == 'new' else (0x3862000, 0x3862400)
        m4 = np.nonzero((a4 >= window[0]) & (a4 < window[1]))[0]
        m8 = np.nonzero((a8 >= window[0]) & (a8 < window[1]))[0]
        emit(f'== {b.version} block{idx}: u32 в окно таблицы {window[0]:#x}..{window[1]:#x}: '
             f'{len(m4)}; u64: {len(m8)}')
        for i in m4[:10]:
            va = b.base + int(i) * 4
            emit(f'   u32 {a4[i]:#010x} @ {va:#x}')
            out.setdefault(f'{state}{idx}', []).append({'kind': 'u32', 'va': hex(va), 'value': hex(int(a4[i]))})
        for i in m8[:10]:
            va = b.base + int(i) * 8
            emit(f'   u64 {a8[i]:#018x} @ {va:#x}')
            out.setdefault(f'{state}{idx}', []).append({'kind': 'u64', 'va': hex(va), 'value': hex(int(a8[i]))})
        # 1) точные адреса записей
        for v in (NEW_TABLE + OLD_TABLE):
            n = int(np.count_nonzero(a4 == v)) + int(np.count_nonzero(a8 == v))
            if n:
                emit(f'   ТОЧНО {v:#x}: {n} вхождений')

emit('\n== окрестности всех найденных указателей')
seen = set()
for state in ('old', 'new'):
    for idx in (0, 1, 2, 3):
        key = f'{state}{idx}'
        if key not in out:
            continue
        b = fwcommon.load('X-H2', state, idx)
        for row in out[key][:6]:
            va = int(row['va'], 16)
            if va in seen:
                continue
            seen.add(va)
            emit(f'--- {b.version} block{idx} @ {va:#x} ({row["kind"]} = {row["value"]})')
            hexdump(b, va, 0x20, 0x40)

(HERE / 'ветка1_указатели.txt').write_text('\n'.join(lines) + '\n', encoding='utf8')
(HERE / 'ветка1_указатели.json').write_text(json.dumps(out, ensure_ascii=False, indent=1), encoding='utf8')
print('saved ветка1_указатели.txt/.json')
