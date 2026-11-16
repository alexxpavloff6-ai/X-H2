# -*- coding: utf-8 -*-
"""Шаг 14: все строки, на которые ссылается код MOVDC-модуля.

Диапазон: X-H2 new 0x30fc000..0x312c000 (старый 0x3100000..0x3130000),
X-H2S 0x3410000..0x3450000, X-T5 0x303e000..0x3078000.
Печатает уникальные строки с адресами и числом ссылок.
"""
import sys, os, json, struct
sys.path.insert(0, r'<корень проекта>\Анализ_прошивки\Сравнение_версий_2026-11-16')
from fwcommon import *  # noqa
import fwcommon

RANGES = {
    ('X-H2', 'old'): (0x3100000, 0x3130000),
    ('X-H2', 'new'): (0x30fc000, 0x312c000),
    ('X-H2S', 'old'): (0x3410000, 0x3450000),
    ('X-H2S', 'new'): (0x3410000, 0x3450000),
    ('X-T5', 'old'): (0x303e000, 0x3078000),
    ('X-T5', 'new'): (0x303e000, 0x3078000),
}


def my_string_refs(b, lo, hi):
    """string_refs с защитой от `add xN,xN,#imm, lsl #12`."""
    out = []
    xs = insns(b, lo, (hi - lo) // 4)
    for i, x in enumerate(xs):
        if x.mnemonic != 'adrp':
            continue
        try:
            page = int(x.op_str.split('#')[1], 0)
        except (ValueError, IndexError):
            continue
        reg = x.op_str.split(',')[0]
        for y in xs[i + 1:i + 5]:
            if y.mnemonic == 'add' and y.op_str.startswith(f'{reg}, {reg}, #'):
                txt = y.op_str.split('#', 1)[1]
                try:
                    imm = int(txt.split(',')[0], 0)
                except ValueError:
                    break
                if 'lsl #12' in y.op_str:
                    break
                s = b.cstr(page + imm)
                if s:
                    out.append((x.address, hex(page + imm), s))
                break
    return out


def main():
    for m in MODELS:
        for st in ('old', 'new'):
            b = load(m, st, 1)
            lo, hi = RANGES[(m, st)]
            strings = my_string_refs(b, lo, hi)
            uniq = {}
            for site, addr, s in strings:
                uniq.setdefault((int(addr, 16), s), []).append(site)
            print(f'=== {m} {st}: строк={len(uniq)} (сайтов {len(strings)})')
            for (addr, s), sites in sorted(uniq.items()):
                print(f'  {addr:#x}  x{len(sites):<3} {s!r}')
            print()


if __name__ == '__main__':
    main()
