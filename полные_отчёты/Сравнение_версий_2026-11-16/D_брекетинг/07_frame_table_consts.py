# -*- coding: utf-8 -*-
"""D: поиск в коде констант, связанных с таблицей кадров, найденной в копировщике
X-H2 0x2dd0418: 0x1cfc000 (база записей), 0x1cfdf00 и 0x1cfdeec (вспомогательные базы).
Идея: кто ещё пользуется этой таблицей — тот и потребитель поля +0x1f48.
Сканирование movz/movk (до 3 инструкций на регистр) по всем блокам old/new.
"""
import sys, struct, json
sys.path.insert(0, r'<корень проекта>\Анализ_прошивки\Сравнение_версий_2026-11-16\D_брекетинг')
from dhelp import *  # noqa

WANTED = {0x1cfc000, 0x1cfdf00, 0x1cfdeec, 0x1cf0000}

def mov_info(w):
    if (w & 0x7f800000) == 0x52800000:
        return ('movz', (w >> 21) & 3, (w >> 5) & 0xffff, w & 31)
    if (w & 0x7f800000) == 0x72800000:
        return ('movk', (w >> 21) & 3, (w >> 5) & 0xffff, w & 31)
    return None

found = []
for m in MODELS:
    for st in ('old', 'new'):
        for idx in (0, 1, 2):
            b = load(m, st, idx)
            data = b.data
            state = {}  # rd -> (va_start, value, steps)
            for o in range(0, len(data) - 3, 4):
                w = struct.unpack_from('<I', data, o)[0]
                va = b.base + o
                info = mov_info(w)
                if not info:
                    state = {}
                    continue
                kind, hw, imm, rd = info
                val = imm << (16 * hw)
                prev = state.get(rd)
                if kind == 'movk' and prev and prev[0] >= va - 8:
                    val |= prev[1] & ~(0xffff << (16 * hw))
                    start = prev[0]
                    steps = prev[2] + 1
                else:
                    start, steps = va, 1
                state[rd] = (start, val, steps)
                if val in WANTED:
                    found.append((f'{m} {st} b{idx}', start, val, rd))
print('найдено:', len(found))
for f in found:
    print(f'{f[0]:>14} {f[1]:#010x} = {f[2]:#x} (w{f[3]})')
