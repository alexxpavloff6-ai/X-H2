# -*- coding: utf-8 -*-
"""Шаг 15: все обращения к структуре настроек (src), из которой копируется флаг.

Ищем только adrp+add, дающие РОВНО базу структуры (не всю страницу), затем
линейно эмулируем от add с уже известным значением регистра.
src: X-H2 old 0x4c3f088 / new 0x4c3b088; X-H2S 0x4bb3e78; X-T5 0x4ac2730.
Блоки 1, 0, 2; диапазон [base, base+0x400).
"""
import sys, os, struct
sys.path.insert(0, r'<корень проекта>\Анализ_прошивки\Сравнение_версий_2026-11-16')
from fwcommon import *  # noqa
import fwcommon, fwemu

SRC = {
    ('X-H2', 'old'): 0x4c3f088,
    ('X-H2', 'new'): 0x4c3b088,
    ('X-H2S', 'old'): 0x4bb3e78,
    ('X-H2S', 'new'): 0x4bb3e78,
    ('X-T5', 'old'): 0x4ac2730,
    ('X-T5', 'new'): 0x4ac2730,
}
SIZE = 0x400


def find_base_sites(b, base):
    """(add_va, reg_index) где adrp+add даёт ровно base."""
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
        txt = x.op_str.split('#', 1)[1]
        try:
            imm = int(txt.split(',')[0], 0)
        except ValueError:
            continue
        if 'lsl' in x.op_str:
            continue
        if imm == want:
            out.append((x.address, f'x{rd}'))
    return out


def emulate_from(b, add_va, regname, lo, hi, maxn=110):
    """Линейная эмуляция с val[regname]=lo (адрес add). Сначала ставим значение."""
    # повторно декодируем add, чтобы знать точку старта
    events = []
    val = {regname: lo}
    # маленький трюк: подменяем «adrp» отсутствием — эмулятор стартует с add+4
    # и не знает val; поэтому сделаем собственную версию через fwemu.emulate,
    # передав начальное значение.
    return fwemu.emulate(b, add_va + 4, maxn, init=val, want=(lo, hi))


if __name__ == '__main__':
    out = []
    for m in MODELS:
        for st in ('old', 'new'):
            base = SRC[(m, st)]
            print(f'=== {m} {st}: src={base:#x}')
            for blk in (1, 0, 2):
                b = load(m, st, blk)
                for add_va, reg in find_base_sites(b, base):
                    for (iva, a, kind, sv, txt) in emulate_from(b, add_va, reg, base, base + SIZE):
                        if not (base <= a < base + SIZE):
                            continue
                        line = (f"{m} {st} b{blk} {iva:#x} {kind} +{a-base:#x} {txt} stored={sv}")
                        print('  ' + line)
                        out.append(line)
            print()
    open(os.path.join(os.path.dirname(os.path.abspath(__file__)), 'src_access.txt'),
         'w', encoding='utf8').write('\n'.join(out))
