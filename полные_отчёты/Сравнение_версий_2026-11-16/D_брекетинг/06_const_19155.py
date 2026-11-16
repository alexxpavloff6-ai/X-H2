# -*- coding: utf-8 -*-
"""D: все места, где в код загружается 32-битное значение 0x19155 (movz+movk),
во всех моделях и блоках old/new. Нужно, чтобы найти другие места работы
с параметром (инициализация/таблицы), кроме самой вставки патча.

Сканируются 32-битные слова (без дизассемблера).
"""
import sys, struct, json
sys.path.insert(0, r'<корень проекта>\Анализ_прошивки\Сравнение_версий_2026-11-16\D_брекетинг')
from dhelp import *  # noqa

WANTED = {0x19155, 0x19154, 0x19156, 0x1915f, 0x19150}

def mov_info(w):
    if (w & 0x7f800000) == 0x52800000:
        return ('movz', (w >> 21) & 3, (w >> 5) & 0xffff, w & 31)
    if (w & 0x7f800000) == 0x72800000:
        return ('movk', (w >> 21) & 3, (w >> 5) & 0xffff, w & 31)
    return None

rows = []
for m in MODELS:
    for st in ('old', 'new'):
        for idx in (0, 1, 2):
            b = load(m, st, idx)
            data = b.data
            prev = None   # (va, kind, hw, imm, rd)
            for o in range(0, len(data) - 7, 4):
                w = struct.unpack_from('<I', data, o)[0]
                info = mov_info(w)
                va = b.base + o
                if not info:
                    prev = None
                    continue
                kind, hw, imm, rd = info
                if prev and prev[4] == rd and prev[0] == va - 4 and prev[1] == 'movz' and kind == 'movk':
                    val = (prev[3] << (16 * prev[2])) | (imm << (16 * hw))
                    if val in WANTED:
                        rows.append((f'{m} {st} b{idx}', va - 4, hex(val), rd, dis(b, va - 4, 6)))
                prev = (va, kind, hw, imm, rd)
print('найдено пар:', len(rows))
for r in rows:
    print(f'--- {r[0]} @ {r[1]:#010x} = {r[2]} (w{r[3]})')
    print('   ', r[4].replace('\n', '\n    '))
