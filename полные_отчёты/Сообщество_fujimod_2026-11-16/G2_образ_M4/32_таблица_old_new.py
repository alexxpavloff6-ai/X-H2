"""32: где в блоке 1 old/new лежит таблица карты регистров и какой код её адресует.

* найти выровненные u32 0xFF970000 (записи таблицы) в old и new → VA;
* для всех ADRP на страницу таблицы разобрать следующую инструкцию ADD/ORR, получить
  абсолютный адрес; оставить только попадания в диапазон таблицы (page+0x000..page+0x400);
* для old/new: сравнить содержимое таблицы (первые 0x80 байт) побайтно.

Только чтение.
"""
import json
import re
import struct
import sys
from pathlib import Path

import numpy as np

HERE = Path(__file__).resolve().parent
sys.path.insert(0, str(HERE))
import m4lib

sys.path.insert(0, str(m4lib.ANALYSIS / 'Сравнение_версий_2026-11-16'))
import fwcommon

out = {}
lines = []


def emit(s=''):
    print(s)
    lines.append(s)


def find_aligned(b, value):
    a = np.frombuffer(b.data[:len(b.data) & ~3], dtype='<u4')
    return [b.base + int(i) * 4 for i in np.nonzero(a == value)[0]]


for state in ('old', 'new'):
    b = fwcommon.load('X-H2', state, 1)
    emit(f'== X-H2 {b.version} block1 base={b.base:#x}')
    for val in (0xFF970000, 0xFF971000, 0xFF90C300, 0xFF974000):
        hits = find_aligned(b, val)
        emit(f'   0x{val:08X}: {len(hits)} → {[hex(h) for h in hits[:8]]}')
        if val == 0xFF970000 and hits:
            va = hits[0]
            o = b.off(va) - 0x30
            for k in range(0, 0x80, 16):
                ch = b.data[o + k:o + k + 16]
                emit(f'     {va - 0x30 + k:09x}  {ch.hex(" "):<47}  ' +
                     ''.join(chr(c) if 32 <= c < 127 else '.' for c in ch))
    out[state] = {'ff970000': [hex(h) for h in find_aligned(b, 0xFF970000)]}

# ADRP + ADD → абсолютные адреса в диапазоне таблицы
emit('\n== разбор ADRP+ADD на страницу 0x385E000 (old/new)')
for state in ('old', 'new'):
    b = fwcommon.load('X-H2', state, 1)
    sites = fwcommon.adrp_sites(b, 0x385E000)
    rows = []
    for s, r in sites:
        reg = f'x{r}'
        for x in fwcommon.insns(b, s + 4, 6):
            if x.mnemonic in ('add', 'adds') and x.op_str.startswith(f'{reg}, {reg}, #'):
                imm = int(x.op_str.split('#')[1], 0)
                tgt = 0x385E000 + imm
                if 0x385E000 <= tgt < 0x385E400:
                    rows.append((s, x.address, hex(tgt)))
                break
            if x.mnemonic in ('ldr', 'str', 'bl', 'b', 'ret'):
                break
    emit(f'  {b.version}: ADRP-сайтов {len(sites)}, попаданий в таблицу 0x385E000..0x385E400: {len(rows)}')
    for s, a, t in rows:
        emit(f'    adrp {s:#x} → add {a:#x} = {t}')
    out.setdefault('table_refs', {})[state] = [{'adrp': hex(s), 'add': hex(a), 'target': t} for s, a, t in rows]

# побайтовое сравнение таблицы old/new (по найденному смещению)
emit('\n== сравнение таблицы (0x80 байт от 0x385E170) old vs new')
bo = fwcommon.load('X-H2', 'old', 1)
bn = fwcommon.load('X-H2', 'new', 1)
so = bo.data[bo.off(0x385E170):bo.off(0x385E170) + 0x80]
sn = bn.data[bn.off(0x385E170):bn.off(0x385E170) + 0x80]
emit(f'  old: {so.hex()}')
emit(f'  new: {sn.hex()}')
emit(f'  идентичны: {so == sn}')
out['table_equal'] = so == sn

(HERE / 'таблица_old_new.txt').write_text('\n'.join(lines) + '\n', encoding='utf8')
(HERE / 'таблица_old_new.json').write_text(json.dumps(out, ensure_ascii=False, indent=1), encoding='utf8')
print('saved таблица_old_new.txt/.json')
