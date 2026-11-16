# -*- coding: utf-8 -*-
"""Шаг 13: кто пишет указатель p = *(state+0x488) (он же out-дескриптор).

Адреса:
  X-H2  old 0x4c33f60 / new 0x4c2ff60
  X-H2S old/new 0x4ba8f58
  X-T5  old/new 0x4ab7310
Сканируем блоки 1, 2, 0.
"""
import sys, os, json
sys.path.insert(0, r'<корень проекта>\Анализ_прошивки\Сравнение_версий_2026-11-16')
from fwcommon import *  # noqa
from fwemu import scan_address

PTR = {
    ('X-H2', 'old'): 0x4c33f60,
    ('X-H2', 'new'): 0x4c2ff60,
    ('X-H2S', 'old'): 0x4ba8f58,
    ('X-H2S', 'new'): 0x4ba8f58,
    ('X-T5', 'old'): 0x4ab7310,
    ('X-T5', 'new'): 0x4ab7310,
}

if __name__ == '__main__':
    out = {}
    for m in MODELS:
        for st in ('old', 'new'):
            tgt = PTR[(m, st)]
            rows = []
            for blk in (1, 2, 0):
                for r in scan_address(m, st, blk, tgt):
                    r['block'] = blk
                    rows.append(r)
            print(f'=== {m} {st}: p_ptr={tgt:#x} hits={len(rows)}')
            for r in rows:
                print("  b%d %s %s %s stored=%s" % (r['block'], r['va'], r['kind'], r['insn'], r['stored']))
            out[f'{m} {st}'] = rows
    open(os.path.join(os.path.dirname(os.path.abspath(__file__)), 'p_ptr_hits.json'),
         'w', encoding='utf8').write(json.dumps(out, ensure_ascii=False, indent=1))
