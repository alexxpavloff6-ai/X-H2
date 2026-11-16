# -*- coding: utf-8 -*-
"""E5: все jump-таблицы-подобные диспетчеры в блоке 0 (br + add со sxtw/sxth),
и все ADRP на страницу 0x128c000 (кто ссылается на район чанков)."""
import sys, re, struct
sys.path.insert(0, r'<корень проекта>\Анализ_прошивки\Сравнение_версий_2026-11-16\E_сеттер_0x2B9')
from ecommon import *  # noqa

MODEL, STATE = 'X-H2', 'new'
b = load(MODEL, STATE, 0)

print('=== ADRP на страницу 0x128c000 и что рядом ===')
for va, reg in adrp_sites(b, 0x128c000):
    print(f'\n--- adrp {va:#x} -> x{reg}')
    dump_range(b, va, va + 0x30)

print('\n=== все br в блоке 0 с контекстом 12 инструкций ===')
cnt = 0
hist = []
for x in all_insns(b):
    if x.mnemonic == '.byte':
        continue
    if x.mnemonic == 'br':
        cnt += 1
        print(f'\n--- br {x.address:#x} (x{x.op_str}) ---')
        for y in hist[-12:]:
            print(f'   {y.address:x}: {y.mnemonic:8} {y.op_str}')
    hist.append(x)
print('всего br:', cnt)
