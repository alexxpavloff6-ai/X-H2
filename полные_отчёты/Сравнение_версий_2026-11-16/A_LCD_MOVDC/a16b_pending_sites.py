# -*- coding: utf-8 -*-
"""Шаг 16b: сайты формирования указателя на pending-блок параметров (X-H2).

pending: old 0x4c3f090 / new 0x4c3b090. Печатаем окрестности и ищем bl.
"""
import sys, os
sys.path.insert(0, r'<корень проекта>\Анализ_прошивки\Сравнение_версий_2026-11-16')
from fwcommon import *  # noqa
import fwemu

PAIRS = {('X-H2', 'old'): 0x4c3f090, ('X-H2', 'new'): 0x4c3b090}


def base_sites(b, base):
    page = base & ~0xfff
    want = base - page
    out = []
    for va, rd in fwemu._adrp_sites_of_page(b, page):
        xs = insns(b, va + 4, 3)
        if not xs:
            continue
        x = xs[0]
        if x.mnemonic != 'add' or not x.op_str.startswith(f'x{rd}, x{rd}, #'):
            continue
        try:
            imm = int(x.op_str.split('#', 1)[1].split(',')[0], 0)
        except ValueError:
            continue
        if 'lsl' in x.op_str:
            continue
        if imm == want:
            out.append((x.address, f'x{rd}'))
    return out


if __name__ == '__main__':
    for (m, st), pend in PAIRS.items():
        b = load(m, st, 1)
        sites = base_sites(b, pend)
        print(f'=== {m} {st} pending={pend:#x} sites={len(sites)}')
        for va, reg in sites:
            print(f'  @{va:#x} ({reg})')
            print('    ' + '\n    '.join(f'{y.address:x}: {y.mnemonic} {y.op_str}'
                                         for y in insns(b, va + 4, 16)))
