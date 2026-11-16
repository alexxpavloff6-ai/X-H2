# -*- coding: utf-8 -*-
"""Шаг 9: кто пишет ПОЛЕ-ИСТОЧНИК флага в структуре настроек.

Писатели флага MOVDC (str w2,[dst+0x43c/0x434]) всего лишь копируют поле из
структуры настроек:
  X-H2  old src 0x4c3f088 (+0x1e4 -> 0x4c3f26c), new src 0x4c3b088 (+0x1e4 -> 0x4c3b26c)
  X-H2S old/new src 0x4bb3e78 (+0x1ec -> 0x4bb4064)
  X-T5  old/new src 0x4ac2730 (+0x284 -> 0x4ac29b4)
Ищем r/w этих адресов в блоках 1 и 0.
"""
import sys, os, json
sys.path.insert(0, r'<корень проекта>\Анализ_прошивки\Сравнение_версий_2026-11-16')
from fwcommon import *  # noqa
from fwemu import scan_address

SRC = {
    ('X-H2', 'old'): 0x4c3f26c,
    ('X-H2', 'new'): 0x4c3b26c,
    ('X-H2S', 'old'): 0x4bb4064,
    ('X-H2S', 'new'): 0x4bb4064,
    ('X-T5', 'old'): 0x4ac29b4,
    ('X-T5', 'new'): 0x4ac29b4,
}

if __name__ == '__main__':
    out = {}
    for m in MODELS:
        for st in ('old', 'new'):
            tgt = SRC[(m, st)]
            rows = []
            for blk in (1, 0):
                for r in scan_address(m, st, blk, tgt):
                    r['block'] = blk
                    rows.append(r)
            print(f'=== {m} {st}: src_field={tgt:#x} hits={len(rows)}')
            for r in rows:
                print("  b%d %s %s %s stored=%s" % (r['block'], r['va'], r['kind'], r['insn'], r['stored']))
            out[f'{m} {st}'] = rows
    open(os.path.join(os.path.dirname(os.path.abspath(__file__)), 'src_field_hits.json'),
         'w', encoding='utf8').write(json.dumps(out, ensure_ascii=False, indent=1))
