"""F: какие adrp+add иммедиаты используются на странице 0x244e000 (X-H2 5.33, b0/b1).

Гипотеза: 0x244eb20 — не «отдельный глобал», а поле структуры, база которой
может быть 0x244eb00 / 0x244ea00 / 0x244e000. Считаем частоту add #imm
сразу после ADRP и распределение целевых адресов.
"""
import sys, re, json, struct, collections
sys.path.insert(0, r'<корень проекта>\Анализ_прошивки\Сравнение_версий_2026-11-16')
from fwcommon import *
import fwcommon

PAGE = 0x244e000


def add_imms(b, page):
    c = collections.Counter()
    for va, reg in adrp_sites(b, page):
        r = f'x{reg}'
        for x in insns(b, va + 4, 3):
            m = re.fullmatch(r'(x\d+), (x\d+), #(-?0x[0-9a-f]+|-?\d+)', x.op_str)
            if x.mnemonic == 'add' and m:
                c[int(m.group(3), 0)] += 1
                break
            if x.mnemonic in ('bl', 'ret', 'br', 'b'):
                break
    return c


for idx in (0, 1):
    b = load('X-H2', 'new', idx)
    c = add_imms(b, PAGE)
    print(f'== X-H2 5.33 b{idx}: {sum(c.values())} adrp+add, иммедиаты:')
    for imm, n in sorted(c.items()):
        print(f'   +{imm:#06x} -> {PAGE+imm:#x}  n={n}')

# то же для 5.30 — сдвинутая страница
for idx in (0, 1):
    b = load('X-H2', 'old', idx)
    c = add_imms(b, 0x2452000)
    print(f'== X-H2 5.30 b{idx}: {sum(c.values())} adrp+add на 0x2452000:')
    for imm, n in sorted(c.items()):
        print(f'   +{imm:#06x} -> {0x2452000+imm:#x}  n={n}')
