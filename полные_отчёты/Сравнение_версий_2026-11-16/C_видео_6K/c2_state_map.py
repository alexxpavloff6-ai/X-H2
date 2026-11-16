# -*- coding: utf-8 -*-
"""Шаг 2 (v3): карта структуры состояния потока (ST) и вызывающих.

ST — глобальная структура потока pm_dec. В коде на неё ссылаются как
    ADRP xN, <page>; ADD xN, xN, #base; LDR/STR [xN, #field]
Скрипт находит все ADRP на эту страницу, определяет base из ADD в prepare-
функции и собирает все последующие LDR/STR [xN,#imm], пока база не
перезаписана или не встретится ветвление/вызов.

Запуск: python c2_state_map.py
Пишет:  c2_state_refs_<model>_<state>.json, c2_state_summary.json, c2_out.txt
"""
import sys, os, json
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from c_common import *  # noqa

HERE = os.path.dirname(os.path.abspath(__file__))

ANCH = {
    'X-H2':  {'old': (0x8fda98, 0x8fdc20, 0x8fdf68), 'new': (0x8fda98, 0x8fdcd8, 0x8fe0d8)},
    'X-H2S': {'old': (0x8f0d30, 0x8f0eb8, 0x8f1200), 'new': (0x8f0d30, 0x8f0f70, 0x8f1370)},
    'X-T5':  {'old': (0x8a2848, 0x8a29d0, 0x8a2d18), 'new': (0x8a2848, 0x8a2a88, 0x8a2e88)},
}


def main():
    summary = {}
    for m in MODELS:
        for st in ('old', 'new'):
            b = load(m, st, 2)
            page, base = find_state_base(b, ANCH[m][st][1])
            rows = base_refs(b, page, base)
            open(os.path.join(HERE, f'c2_state_refs_{m}_{st}.json'), 'w', encoding='utf8').write(
                json.dumps({'page': hex(page), 'base': hex(base), 'refs': rows},
                           ensure_ascii=False, indent=1))
            fields = {}
            for r in rows:
                fields.setdefault(r['rel'], []).append(r)
            print(f'===== {m} {st}: page={page:#x} base={base:#x}, '
                  f'{len(rows)} обращений, {len(fields)} полей')
            for f in sorted(fields):
                if f < 0 or f > 0x2000:
                    continue
                rs = fields[f]
                def kchar(r):
                    k = r['kind']
                    return 'W' if k.startswith('str') else 'R'
                kinds = ''.join(sorted({kchar(r) for r in rs}))
                print(f'   ST+{f:#06x} [{len(rs)}] {kinds}: ' +
                      ' '.join(hex(r['site']) for r in sorted(rs, key=lambda z: z['site'])[:8]))
            summary[f'{m} {st}'] = {'page': hex(page), 'base': hex(base),
                                    'fields': {hex(k): [hex(r['site']) for r in v]
                                               for k, v in sorted(fields.items())}}
            for name, va in zip(('helper', 'prepare', 'completion'), ANCH[m][st]):
                cs = bl_callers(b, va)
                print(f'   callers of {name} {va:#x}: {[hex(a) for a, k in cs]}')
    open(os.path.join(HERE, 'c2_state_summary.json'), 'w', encoding='utf8').write(
        json.dumps(summary, ensure_ascii=False, indent=1))


if __name__ == '__main__':
    main()
