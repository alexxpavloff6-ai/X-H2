# -*- coding: utf-8 -*-
"""Шаг 6b: точные сайты вычисления базы MOVDC-структуры (page+imm == base).

Для каждого сайта печатаем окно 40 инструкций и помечаем:
  * str/strb/strh со смещением 0x43c (X-H2/X-T5) или 0x434 (X-H2S) — прямая запись флага;
  * bl — возможная передача базы в callee (x0 = base).
"""
import sys, os, json
sys.path.insert(0, r'<корень проекта>\Анализ_прошивки\Сравнение_версий_2026-11-16')
from fwcommon import *  # noqa
import fwcommon, struct

HERE = os.path.dirname(os.path.abspath(__file__))
BASE = {
    ('X-H2', 'old'): (0x4c33ad8, 0x43c),
    ('X-H2', 'new'): (0x4c2fad8, 0x43c),
    ('X-H2S', 'old'): (0x4ba8ad8, 0x434),
    ('X-H2S', 'new'): (0x4ba8ad8, 0x434),
    ('X-T5', 'old'): (0x4ab6e88, 0x43c),
    ('X-T5', 'new'): (0x4ab6e88, 0x43c),
}


def adrp_map(b):
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
            base_va, foff = BASE[(m, st)]
            am = adrp_map(b)
            hits = []
            for ava in am:
                for k in range(1, 9):
                    xs = insns(b, ava + 4 * k, 1)
                    if not xs:
                        break
                    x = xs[0]
                    ops = [p.strip() for p in x.op_str.split(',')]
                    if x.mnemonic in ('bl', 'b', 'ret'):
                        break
                    if x.mnemonic == 'add' and len(ops) == 3 and ops[0] == ops[1] and ops[2].startswith('#'):
                        try:
                            imm = int(ops[2][1:].split(',')[0], 0)
                        except ValueError:
                            continue
                        tgt = am[ava][0] + imm
                        if tgt == base_va:
                            hits.append((ava, x.address, x.op_str))
            print(f'=== {m} {st}: base={base_va:#x} flag=+{foff:#x} sites={len(hits)}')
            recs = []
            for ava, add_va, ops in hits:
                txt = []
                for y in insns(b, add_va + 4, 48):
                    mark = ''
                    if y.mnemonic.startswith('str') and f'#0x{foff:x}]' in y.op_str:
                        mark = '   <<< WRITE FLAG?'
                    if y.mnemonic == 'bl':
                        mark = '   <-- call'
                    if y.mnemonic == 'ret':
                        txt.append(f'      {y.address:x}: ret')
                        break
                    txt.append(f'      {y.address:x}: {y.mnemonic} {y.op_str}{mark}')
                print(f'  -- adrp@{ava:#x} add@{add_va:#x} ({ops})')
                print('\n'.join(txt))
                recs.append({'adrp': hex(ava), 'add': hex(add_va), 'ops': ops})
            out[f'{m} {st}'] = recs
    open(os.path.join(HERE, 'struct_base_sites.json'), 'w', encoding='utf8').write(
        json.dumps(out, ensure_ascii=False, indent=1))


if __name__ == '__main__':
    main()
