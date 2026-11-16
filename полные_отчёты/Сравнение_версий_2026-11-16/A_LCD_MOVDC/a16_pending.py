# -*- coding: utf-8 -*-
"""Шаг 16: кто заполняет «pending» копию параметров (0x4c3b090) и её поле +0x74.

Параметрический блок продублирован: pending 0x4c3b090 -> current 0x4c3b1f8
(memcpy 0x168 байт в 0x31015b4). Флаг = current+0x74 = pending+0x74
(= 0x4c3b088+0x1e4 = 0x4c3b26c).
Ищем: (a) adrp+add на 0x4c3b090 и последующий bl (memcpy) — кто пишет pending;
       (b) писателей 0x4c3b104 (= pending+0x74).
"""
import sys, os
sys.path.insert(0, r'<корень проекта>\Анализ_прошивки\Сравнение_версий_2026-11-16')
from fwcommon import *  # noqa
import fwcommon, fwemu

PEND = {
    ('X-H2', 'old'): (0x4c3f090, 0x4c3f104),
    ('X-H2', 'new'): (0x4c3b090, 0x4c3b104),
    ('X-H2S', 'old'): (0x4bb3e80, 0x4bb3ef4),   # по аналогии: src_base-8 = pending? уточним
    ('X-H2S', 'new'): (0x4bb3e80, 0x4bb3ef4),
    ('X-T5', 'old'): (0x4ac2738, 0x4ac27ac),
    ('X-T5', 'new'): (0x4ac2738, 0x4ac27ac),
}


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
    for m in MODELS:
        for st in ('old', 'new'):
            pend, field = PEND[(m, st)]
            b = load(m, st, 1)
            print(f'=== {m} {st}: pending={pend:#x} field={field:#x}')
            print('  -- сайты adrp+add на pending (и что дальше):')
            for va, reg in base_sites(b, pend)[:20]:
                print(f'    @{va:#x} ({reg})')
                print('      ' + '\n      '.join(
                    f'{y.address:x}: {y.mnemonic} {y.op_str}' for y in insns(b, va + 4, 12)))
            print('  -- r/w поля pending+0x74:')
            for r in fwemu.scan_address(m, st, 1, field):
                print(f"    {r['va']} {r['kind']} {r['insn']} stored={r['stored']}")
            print()
