# -*- coding: utf-8 -*-
"""E44: кто пишет src+0x1c4 для двух источников построителя job (0x38de1d8 и 0x38decc8),
и что за путь выбирается (сравнение/условия вокруг вызовов 0x2ff1ed8)."""
import sys, re
sys.path.insert(0, r'<корень проекта>\Анализ_прошивки\Сравнение_версий_2026-11-16\E_сеттер_0x2B9')
from ecommon import *  # noqa

b = load('X-H2', 'new', 1)
PAGE = 0x38de000

def find_str(imm):
    out = []
    for x in all_insns(b):
        if x.mnemonic == '.byte':
            continue
        if x.mnemonic.startswith('str') and re.search(r'\[x\d+, #%#x\]' % imm, x.op_str):
            out.append(x)
    return out

for imm, name in ((0x39c, 'src1+0x1c4 (0x38de1d8)'), (0xe8c, 'src2+0x1c4 (0x38decc8)')):
    print(f'\n=== записи [{name}] : ищем adrp 0x38de000 рядом ===')
    for x in find_str(imm):
        hist = [y for y in all_insns(b, max(b.base, x.address - 0x80), x.address) if y.mnemonic != '.byte']
        adr = [(y.address, y.op_str) for y in hist if y.mnemonic == 'adrp' and '0x38de000' in y.op_str]
        if adr:
            print(f'\n  запись {x.address:#x}: {x.mnemonic} {x.op_str}; adrp: {[(hex(a), t) for a, t in adr]}')
            for y in hist[-10:]:
                print(f'     {y.address:x}: {y.mnemonic:8} {y.op_str}')

print('\n=== условия вокруг вызовов 0x2ff1ed8 ===')
for a in (0x2fd229c, 0x2ff8ec8, 0x2ff92f4):
    print(f'\n--- {a:#x}')
    for y in all_insns(b, a - 0x60, a + 0x10):
        if y.mnemonic != '.byte':
            print(f'   {y.address:x}: {y.mnemonic:8} {y.op_str}')
