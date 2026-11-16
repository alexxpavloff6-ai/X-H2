# -*- coding: utf-8 -*-
"""Шаг 10: найти функции, ссылающиеся на строку 'MOVDC', и распечатать их.

Строки MOVDC: X-H2 old 0x37a7b3a/0x37d0178; new 0x37a3b3a/0x37cc178;
X-H2S 0x3a20d6a/0x3a467a0; X-T5 0x36d3f1a/0x36fc508.
Ищем ADRP+ADD на эти адреса в блоке 1 (и 0), печатаем контекст и старт функции.
"""
import sys, os, json
sys.path.insert(0, r'<корень проекта>\Анализ_прошивки\Сравнение_версий_2026-11-16')
from fwcommon import *  # noqa
import struct


def adrp_add_sites(b, target):
    out = []
    page = target & ~0xfff
    lo = target - page
    data, base = b.data, b.base
    for o in range(0, len(data) - 3, 4):
        w = struct.unpack_from('<I', data, o)[0]
        if (w & 0x9f000000) != 0x90000000:
            continue
        t = sys.modules['fwcommon']._adrp_target(w, base + o)
        if not t or t[0] != page:
            continue
        rd = t[1]
        # смотрим 1-3 инструкции вперёд на add rd,rd,#imm
        for k in range(1, 4):
            xs = insns(b, base + o + 4 * k, 1)
            if not xs:
                break
            x = xs[0]
            if x.mnemonic == 'add' and x.op_str.startswith(f'x{rd}, x{rd}, #'):
                imm = int(x.op_str.split('#')[1], 0)
                if imm == lo:
                    out.append((base + o, x.address))
                break
    return out


STRINGS = {
    ('X-H2', 'old'): [0x37a7b3a, 0x37d0178],
    ('X-H2', 'new'): [0x37a3b3a, 0x37cc178],
    ('X-H2S', 'old'): [0x3a20d6a, 0x3a467a0],
    ('X-H2S', 'new'): [0x3a20d6a, 0x3a467a0],
    ('X-T5', 'old'): [0x36d3f1a, 0x36fc508],
    ('X-T5', 'new'): [0x36d3f1a, 0x36fc508],
}

if __name__ == '__main__':
    for m in MODELS:
        for st in ('old', 'new'):
            for blk in (1, 0):
                b = load(m, st, blk)
                for s in STRINGS[(m, st)]:
                    sites = adrp_add_sites(b, s)
                    if not sites:
                        continue
                    print(f'--- {m} {st} b{blk} string {s:#x} ({b.cstr(s)!r}) sites={[(hex(a),hex(c)) for a,c in sites]}')
                    for a, c in sites:
                        fs = func_start(b, a)
                        print(f'    func_start={fs and hex(fs)}')
                        print(dis(b, (a - 0x30), 26))
