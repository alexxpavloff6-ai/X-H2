# -*- coding: utf-8 -*-
"""Шаг 6: кто вычисляет базу MOVDC-структуры (adrp+add) и куда её передают.

Базы: X-H2 old 0x4c33ad8 / new 0x4c2fad8; X-H2S 0x4ba8ad8; X-T5 0x4ab6e88.
Ищем все `add xN, xN, #imm`, у которых adrp на той же странице, и page+imm
попадает в [base, base+0x800). Для каждого — окно вперёд: есть ли bl (передача
базы в callee), ldr/str, mov/пересылка в другой регистр.
"""
import sys, os, json
sys.path.insert(0, r'<корень проекта>\Анализ_прошивки\Сравнение_версий_2026-11-16')
from fwcommon import *  # noqa
import fwcommon
import struct

HERE = os.path.dirname(os.path.abspath(__file__))
BASE = {
    ('X-H2', 'old'): 0x4c33ad8,
    ('X-H2', 'new'): 0x4c2fad8,
    ('X-H2S', 'old'): 0x4ba8ad8,
    ('X-H2S', 'new'): 0x4ba8ad8,
    ('X-T5', 'old'): 0x4ab6e88,
    ('X-T5', 'new'): 0x4ab6e88,
}


def adrp_map(b):
    """va -> (page, rd) для всех ADRP."""
    m = {}
    data, base = b.data, b.base
    for o in range(0, len(data) - 3, 4):
        w = struct.unpack_from('<I', data, o)[0]
        if (w & 0x9f000000) == 0x90000000:
            t = fwcommon._adrp_target(w, base + o)
            if t:
                m[base + o] = t
    return m


def main():
    out = {}
    for m in MODELS:
        for st in ('old', 'new'):
            b = load(m, st, 1)
            base_va = BASE[(m, st)]
            page = base_va & ~0xfff
            am = adrp_map(b)
            hits = []
            # добавляем только те, где есть ADD с imm, попадающим в окно базы
            for va, words in am.items():
                pass
            # проходим по всем add-инструкциям в пределах 6 инструкций после adrp
            for ava in am:
                for k in range(1, 8):
                    xs = insns(b, ava + 4 * k, 1)
                    if not xs:
                        break
                    x = xs[0]
                    ops = [p.strip() for p in x.op_str.split(',')]
                    if x.mnemonic == 'bl' or x.mnemonic == 'b' or x.mnemonic == 'ret':
                        break
                    if x.mnemonic == 'add' and len(ops) == 3 and ops[0] == ops[1] and ops[2].startswith('#'):
                        try:
                            imm = int(ops[2][1:].split(',')[0], 0)
                        except ValueError:
                            continue
                        if ', lsl' in x.op_str:
                            continue
                        tgt = am[ava][0] + imm
                        if base_va <= tgt < base_va + 0x800:
                            hits.append((ava, x.address, tgt, x.op_str))
            print(f'=== {m} {st}: base={base_va:#x}  add-hits={len(hits)}')
            for ava, add_va, tgt, ops in hits:
                print(f'  adrp@{ava:#x}  add@{add_va:#x} -> {tgt:#x}  ({ops})')
                for y in insns(b, add_va + 4, 14):
                    print(f'      {y.address:x}: {y.mnemonic} {y.op_str}')
            out[f'{m} {st}'] = [{'adrp': hex(a), 'add': hex(c), 'tgt': hex(t)} for a, c, t, _ in hits]
    open(os.path.join(HERE, 'struct_base_users.json'), 'w', encoding='utf8').write(
        json.dumps(out, ensure_ascii=False, indent=1))


if __name__ == '__main__':
    main()
