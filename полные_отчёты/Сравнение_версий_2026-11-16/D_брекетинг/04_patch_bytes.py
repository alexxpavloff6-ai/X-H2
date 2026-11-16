# -*- coding: utf-8 -*-
"""D: найти вставку `mov w0,#0x9155; movk w0,#1,lsl#16` (байтовый образец) во всех
моделях и блоках old/new; подтвердить, что это тот самый патч и получить адреса.
"""
import sys, struct
sys.path.insert(0, r'<корень проекта>\Анализ_прошивки\Сравнение_версий_2026-11-16\D_брекетинг')
from dhelp import *  # noqa

MOVZ = struct.pack('<I', 0x52800000 | (0x9155 << 5))          # mov w0,#0x9155
MOVK = struct.pack('<I', 0x72800000 | (1 << 21) | (1 << 5))   # movk w0,#1,lsl#16
print('образец:', (MOVZ + MOVK).hex())
for m in MODELS:
    for st in ('old', 'new'):
        for idx in (0, 1, 2):
            b = load(m, st, idx)
            hits = find_bytes(b, MOVZ + MOVK)
            print(f'{m} {st} b{idx}: {[hex(h) for h in hits]}')
            for h in hits:
                print('   ', dis(b, h, 10).replace('\n', '\n    '))
