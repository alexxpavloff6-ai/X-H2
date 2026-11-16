# -*- coding: utf-8 -*-
"""D: обращения к структуре per-frame (X-H2 +0x1f48, X-T5 +0x1050), old+new.
Использует полное дизассемблирование блока (dhelp.all_insns)."""
import sys, re, json
sys.path.insert(0, r'<корень проекта>\Анализ_прошивки\Сравнение_версий_2026-11-16\D_брекетинг')
from dhelp import *  # noqa

TARGETS = {'X-H2': [0x1f48], 'X-H2S': [0x1f48, 0x1050], 'X-T5': [0x1050]}
res = {}
for m in MODELS:
    for st in ('old', 'new'):
        for idx in (0, 1, 2):
            b = load(m, st, idx)
            for imm in TARGETS[m]:
                hits = mem_refs(b, imm)
                if hits:
                    key = f'{m} {st} b{idx} #{imm:x}'
                    res[key] = [f'{x.address:#x}: {x.mnemonic} {x.op_str}' for x in hits]
                    print(f'--- {key} ({len(hits)})')
                    for x in hits:
                        print(f'    {x.address:#x}: {x.mnemonic} {x.op_str}')
open('struct_offsets_mem.json', 'w', encoding='utf8').write(json.dumps(res, ensure_ascii=False, indent=1))
