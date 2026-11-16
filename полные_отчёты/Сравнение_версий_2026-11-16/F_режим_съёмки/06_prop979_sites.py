"""F: где в коде встречается id свойства 0x979 (mov w0,#0x979) — все блоки/модели.

Также ищем id 0x90a (рядом в той же функции-отправителе) и 0x858 (из 0x11359d4).
"""
import sys, re, json, struct
sys.path.insert(0, r'<корень проекта>\Анализ_прошивки\Сравнение_версий_2026-11-16')
from fwcommon import *

IDS = (0x979, 0x90a, 0x858, 0x2b9)
res = {}
for model in MODELS:
    for state in ('old', 'new'):
        for idx in (0, 1, 2):
            b = load(model, state, idx)
            hits = []
            for va, w in iter_words(b):
                # movz w0, #imm  (0x52800000 | imm16<<5 | rd)
                if (w & 0xffe0001f) == 0x52800000:
                    imm = (w >> 5) & 0xffff
                    if imm in IDS:
                        hits.append((va, imm, (w >> 0) & 31))
            if hits:
                print(f'== {model} {b.version} b{idx}: {len(hits)}')
                for va, imm, rd in hits:
                    print(f'   {va:x}: mov w{rd}, #{imm:#x}')
            res[f'{model} {b.version} b{idx}'] = hits
json.dump({k: [[hex(a), i, r] for a, i, r in v] for k, v in res.items()},
          open('prop979_sites.json', 'w'), indent=1)
