# -*- coding: utf-8 -*-
"""E42: найти запись [0x4daa6e8] (указатель job) и конструктор job.
Идея: перебрать все `str x?,[x?, #0x28]` и проверить, что база — регистр,
получивший 0x4daa6c0 через adrp 0x4daa000 + add #0x6c0 в той же функции.
"""
import sys, re, struct
sys.path.insert(0, r'<корень проекта>\Анализ_прошивки\Сравнение_версий_2026-11-16\E_сеттер_0x2B9')
from ecommon import *  # noqa

b = load('X-H2', 'new', 1)
# 1) все места, где регистр получает 0x4daa6c0
anchors = []   # (addr, reg)
for va, reg in adrp_sites(b, 0x4daa000):
    for x in all_insns(b, va + 4, va + 0x10):
        if x.mnemonic == 'add':
            m = re.match(r'(x\d+), (x\d+), #0x6c0$', x.op_str)
            if m and int(m.group(2)[1:]) == reg:
                anchors.append((x.address, m.group(1)))
print('мест загрузки адреса менеджера 0x4daa6c0:', len(anchors))

# 2) для каждого — смотрим вперёд до конца функции, ищем записи по этому регистру
for a, reg in anchors:
    # конец функции
    end = a + 0x400
    stores = []
    for x in all_insns(b, a, end):
        if x.mnemonic == '.byte':
            continue
        if x.mnemonic in ('str', 'strb', 'strh', 'stp') and re.search(r'\[%s(,| \])' % reg, x.op_str):
            off = re.search(r', #(0x[0-9a-f]+|\d+)\]', x.op_str)
            stores.append((x.address, int(off.group(1), 0) if off else 0, f'{x.mnemonic} {x.op_str}'))
        if x.mnemonic == 'ret':
            break
    if stores:
        print(f'\n--- менеджер загружен {a:#x} ({reg}) ---')
        for s in stores:
            print(f'   {s[0]:#x} off {s[1]:#x}: {s[2]}')
