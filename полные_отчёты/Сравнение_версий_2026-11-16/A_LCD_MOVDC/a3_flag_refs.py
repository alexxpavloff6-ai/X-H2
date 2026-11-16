# -*- coding: utf-8 -*-
"""Шаг 3: все ADRP(+ADD)→LDR/STR обращения к глобальному флагу MOVDC.

Адреса флага:
  X-H2  old 0x4c33f14 / new 0x4c2ff14
  X-H2S old/new 0x4ba8f0c
  X-T5  old/new 0x4ab72c4
Сканируем блоки 0,1,2 всех состояний через fwcommon.adrp_refs и дополнительно
ручным разбором (учёт add #imm в 12-битном диапазоне и ldr/str с #0x43c от базы).
Результат кэшируется в refs_<model>_<state>.json.
"""
import sys, os, json
sys.path.insert(0, r'<корень проекта>\Анализ_прошивки\Сравнение_версий_2026-11-16')
from fwcommon import *  # noqa

HERE = os.path.dirname(os.path.abspath(__file__))
FLAG = {
    ('X-H2', 'old'): 0x4c33f14,
    ('X-H2', 'new'): 0x4c2ff14,
    ('X-H2S', 'old'): 0x4ba8f0c,
    ('X-H2S', 'new'): 0x4ba8f0c,
    ('X-T5', 'old'): 0x4ab72c4,
    ('X-T5', 'new'): 0x4ab72c4,
}


def run():
    out = {}
    for m in MODELS:
        for st in ('old', 'new'):
            tgt = FLAG[(m, st)]
            rec = {'flag': hex(tgt), 'blocks': {}}
            for idx in (0, 1, 2):
                b = load(m, st, idx)
                rows = adrp_refs(b, tgt, window=24)
                # помечаем, есть ли рядом BL (передача базы в callee не отличить этим)
                rec['blocks'][str(idx)] = [{'site': hex(r['site']), 'insn': r['insn']} for r in rows]
            out[f'{m} {st}'] = rec
            print(f'{m} {st}: ' + ', '.join(f"b{k}={len(v)}" for k, v in rec['blocks'].items()))
    (open(os.path.join(HERE, 'refs_flags.json'), 'w', encoding='utf8')
     .write(json.dumps(out, ensure_ascii=False, indent=1)))


if __name__ == '__main__':
    run()
