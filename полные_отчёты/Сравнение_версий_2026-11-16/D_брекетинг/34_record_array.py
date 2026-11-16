# -*- coding: utf-8 -*-
"""D3: кто ещё работает с массивом записей ctx+0x5ca8, где лежит структура params
(0x68 байт в начале записи 0xC8), и кто читает поле +0x60.

В 0x2dd1bb0: x22 = ctx+0x5ca8 (0x2dd1f40: add x22,x19,#5,lsl#12; add x22,x22,#0xca8),
записи идут с шагом 0xC8; params = начало записи.
Ищем в блоке 1 все места, где вычисляется ctx+0x5ca8, и печатаем их контекст плюс
все чтения [x?,#0x60] в тех же функциях.
"""
import sys, re, struct
sys.path.insert(0, r'<корень проекта>\Анализ_прошивки\Сравнение_версий_2026-11-16\D_брекетинг')
from dhelp import *  # noqa

model, state = 'X-H2', 'new'
b = load(model, state, 1)
d = b.data

# ищем `add xN, xM, #5, lsl #12` (imm12=0x500? для add с lsl#12: imm12=5, shift=12)
# кодировка ADD (immediate): 0x91000000 | (shift<<22) | (imm12<<10) | (Rn<<5) | Rd
def is_add_lsl12_5(w):
    if (w & 0x7f800000) != 0x11000000:  # ADD imm, 64-bit
        return None
    shift = (w >> 22) & 3
    if shift != 1:      # lsl #12
        return None
    imm = (w >> 10) & 0xfff
    if imm != 5:
        return None
    return w & 31, (w >> 5) & 31

hits = []
for o in range(0, len(d) - 8, 4):
    w = struct.unpack_from('<I', d, o)[0]
    r = is_add_lsl12_5(w)
    if not r:
        continue
    rd, rn = r
    w2 = struct.unpack_from('<I', d, o + 4)[0]
    # следующий add той же Rd с imm12 == 0xca8
    if (w2 & 0x7f800000) == 0x11000000 and ((w2 >> 22) & 3) == 0 and ((w2 >> 10) & 0xfff) == 0xca8:
        if (w2 & 0x1f) == rd and ((w2 >> 5) & 0x1f) == rd:
            hits.append(b.base + o)

print(f'мест с ctx+0x5ca8: {len(hits)}')
for a in hits:
    print(f'\n--- {a:#x}')
    print(dis(b, a - 0x10, 10))
