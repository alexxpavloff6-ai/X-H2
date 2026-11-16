# -*- coding: utf-8 -*-
"""E35: кто формирует структуру задания (job), у которой +0x140 — указатель буфера,
а +0x144 — код режима (его копирует 0x30871ac в ctx+0x3978).
Ищем функции, где есть и `str x?,[xN,#0x140]`, и `str w?,[xN,#0x144]`."""
import sys, re, struct
sys.path.insert(0, r'<корень проекта>\Анализ_прошивки\Сравнение_версий_2026-11-16\E_сеттер_0x2B9')
from ecommon import *  # noqa

b = load('X-H2', 'new', 1)
w144 = []
for x in all_insns(b):
    if x.mnemonic == '.byte':
        continue
    if x.mnemonic in ('str', 'strb', 'strh') and re.search(r'\[x\d+, #0x144\]', x.op_str):
        w144.append(x)
print('писателей +0x144:', len(w144))
for x in w144:
    st = find_prologue(b, x.address, limit=0x4000)
    if not st or x.address - st > 0x4000:
        continue
    fn = [y for y in all_insns(b, st, min(x.address + 0x200, b.end)) if y.mnemonic != '.byte']
    writes140 = [y for y in fn if y.mnemonic == 'str' and re.match(r'x\d+,', y.op_str) and re.search(r'\[x\d+, #0x140\]', y.op_str)]
    if writes140:
        print(f'\n### функция {st:#x}, запись +0x144 в {x.address:#x}; +0x140 (x) в {[hex(y.address) for y in writes140]}')
        for y in all_insns(b, x.address - 0x30, x.address + 8):
            if y.mnemonic != '.byte':
                print(f'   {y.address:x}: {y.mnemonic:8} {y.op_str}')
