# -*- coding: utf-8 -*-
"""E33: как вызывается blob-сеттер 0x1492040: id/значение из памяти (внешняя команда)
против констант. Печатаем примеры «id из памяти»."""
import sys, re, struct
sys.path.insert(0, r'<корень проекта>\Анализ_прошивки\Сравнение_версий_2026-11-16\E_сеттер_0x2B9')
from ecommon import *  # noqa

b0 = load('X-H2', 'new', 0)
b1 = load('X-H2', 'new', 1)
SET = 0x1492040
rows = []
for blk in (b0, b1):
    for a, k in bl_callers(blk, SET):
        if k != 'bl':
            continue
        hist = [x for x in all_insns(blk, a - 0x20, a) if x.mnemonic != '.byte']
        rows.append((blk, a, hist))
print('всего вызовов 0x1492040:', len(rows))
mem_id, mem_val, const = [], [], 0
for blk, a, hist in rows:
    id_mem = any(x.mnemonic in ('ldrh', 'ldrb', 'ldr') and re.match(r'w0,', x.op_str) for x in hist[-6:])
    val_mem = any(x.mnemonic in ('ldrh', 'ldrb', 'ldr') and re.match(r'w1,', x.op_str) for x in hist[-6:])
    if id_mem:
        mem_id.append((blk, a, hist))
    elif val_mem:
        mem_val.append((blk, a, hist))
print(f'id из памяти: {len(mem_id)}; значение из памяти: {len(mem_val)}')
for blk, a, hist in mem_id[:6]:
    print(f'\n--- {a:#x} (блок {blk.idx})')
    for y in hist[-10:]:
        print(f'   {y.address:x}: {y.mnemonic:8} {y.op_str}')
