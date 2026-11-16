"""39: (а) есть ли ГДЕ-ЛИБО ADRP на страницы MOVDC (0xFF970000/1000/2000/3000) — блоки 0-3
old/new + префикс-загрузчик;
(б) побайтовая сверка таблицы карты регистров old 5.30 @0x386214C vs new 5.33 @0x385E14C
(с учётом сдвига -0x4000);
(в) разбор записей таблицы (6 слов по 24 байта) и поиск ссылок на таблицу как на данные
(4- и 8-байтные значения 0x385E14C/0x385E170/0x385D14C).

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


# ---------------------------------------------------------------- (а) ADRP на страницы MOVDC
emit('== (а) ADRP на страницы MOVDC по всем блокам и префиксу')
PAGES = (0xFF970000, 0xFF971000, 0xFF972000, 0xFF973000, 0xFF974000)
dec = m4lib.load_dat(m4lib.DAT_NEW)['dec']
found = {}
for state in ('old', 'new'):
    for idx in (0, 1, 2, 3):
        b = fwcommon.load('X-H2', state, idx)
        for p in PAGES:
            s = fwcommon.adrp_sites(b, p)
            if s:
                found[f'{state} block{idx} {p:#x}'] = [hex(x) for x, _ in s[:6]]
emit(f'  найдено комбинаций: {len(found)}')
for k, v in found.items():
    emit(f'   {k}: {v}')
out['adrp_movdc_pages'] = found


class Buf:
    def __init__(self, data, base):
        self.data, self.base = data, base


prefix = Buf(dec[:0x300274], 0)
for p in PAGES:
    s = fwcommon.adrp_sites(prefix, p)
    if s:
        emit(f'   prefix {p:#x}: {[hex(x) for x, _ in s[:6]]}')
        out.setdefault('adrp_prefix', {})[hex(p)] = [hex(x) for x, _ in s[:6]]
if not out.get('adrp_prefix'):
    emit('   префикс: ADRP на страницы MOVDC нет')

# ---------------------------------------------------------------- (б) таблица old vs new
emit('\n== (б) таблица карты регистров: old 5.30 @0x386214C vs new 5.33 @0x385E14C')
bo = fwcommon.load('X-H2', 'old', 1)
bn = fwcommon.load('X-H2', 'new', 1)
LEN = 0x100
so = bo.data[bo.off(0x386214C):bo.off(0x386214C) + LEN]
sn = bn.data[bn.off(0x385E14C):bn.off(0x385E14C) + LEN]
emit(f'  old[0x386214C +{LEN:#x}]: {so.hex()}')
emit(f'  new[0x385E14C +{LEN:#x}]: {sn.hex()}')
emit(f'  побайтно идентичны: {so == sn}')
out['table_identical'] = so == sn

# записи по 24 байта
emit('  записи {start, end, clock, 1, 1, count}:')
recs = []
for k in range(0, LEN, 24):
    if k + 24 > LEN:
        break
    vals = struct.unpack_from('<6I', sn, k)
    recs.append([hex(v) for v in vals])
    emit(f'   +{0x385E14C + k:#x}: ' + ' '.join(f'{v:#010x}' for v in vals))
out['records'] = recs

# ---------------------------------------------------------------- (в) ссылки на таблицу как на данные
emit('\n== (в) ссылки на таблицу как на данные (4/8-байтные значения)')
TGT = (0x385E14C, 0x385E170, 0x385E130, 0x385D14C, 0x385D170)
for state in ('old', 'new'):
    for idx in (0, 1, 2):
        b = fwcommon.load('X-H2', state, idx)
        for v in TGT:
            n4 = b.data.count(struct.pack('<I', v))
            n8 = b.data.count(struct.pack('<Q', v))
            if n4 or n8:
                emit(f'   {state} block{idx}: {v:#x} → u32={n4} u64={n8}')

(HERE / 'movdc_карта_итог.txt').write_text('\n'.join(lines) + '\n', encoding='utf8')
(HERE / 'movdc_карта_итог.json').write_text(json.dumps(out, ensure_ascii=False, indent=1), encoding='utf8')
print('saved movdc_карта_итог.txt/.json')
