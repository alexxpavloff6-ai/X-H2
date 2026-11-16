# -*- coding: utf-8 -*-
"""E24: все записи [xN,#0x144] в блоке 1 с контекстом — ищем, кто заполняет
поле режима в структуре задания RECF (и откуда значение)."""
import sys, re, struct
sys.path.insert(0, r'<корень проекта>\Анализ_прошивки\Сравнение_версий_2026-11-16\E_сеттер_0x2B9')
from ecommon import *  # noqa

MODEL, STATE = 'X-H2', 'new'
b = load(MODEL, STATE, 1)

writes = []
for x in all_insns(b):
    if x.mnemonic == '.byte':
        continue
    if x.mnemonic in ('str', 'strh', 'strb', 'stur', 'sturh', 'sturb') and re.search(r'\[x\d+, #0x144\]', x.op_str):
        writes.append(x)
print('записей [xN,#0x144]:', len(writes))
for x in writes:
    print(f'\n=== {x.address:#x}: {x.mnemonic} {x.op_str} ===')
    for y in all_insns(b, x.address - 0x3c, x.address):
        if y.mnemonic != '.byte':
            print(f'   {y.address:x}: {y.mnemonic:8} {y.op_str}')
