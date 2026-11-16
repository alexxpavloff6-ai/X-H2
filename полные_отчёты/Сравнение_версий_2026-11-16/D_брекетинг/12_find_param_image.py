# -*- coding: utf-8 -*-
"""D: попытка найти сам образ параметров (blob), который копируется в RAM по
0x27008000 из адреса 0x7503000 (0xC6C00 байт).

Признак из кода инициализации (X-H2 5.33, блок 0, 0x14924f4): u16 по смещению
+0x202 должен быть 0xAA55. Ищем в декодированном DAT (XOR 0xFF, только чтение)
такие места, где от pos-0x202 начинается правдоподобный образ параметров.
"""
import sys, struct, re
sys.path.insert(0, r'<корень проекта>\Анализ_прошивки\Сравнение_версий_2026-11-16\D_брекетинг')
from dhelp import *  # noqa

DAT = r'<корень проекта>\FIRMWARE\ver new\FWUP0028 (2).DAT'
raw = open(DAT, 'rb').read()
dec = raw.translate(bytes.maketrans(bytes(range(256)), bytes(255 - i for i in range(256))))
print('DAT size', hex(len(dec)))

hits = [m.start() for m in re.finditer(b'\x55\xaa', dec)]
print('вхождений 0xaa55 (le):', len(hits))
cand = []
for pos in hits:
    s = pos - 0x202
    if s < 0:
        continue
    if s + 0xc6c00 > len(dec):
        continue
    # образ не должен быть целиком 00/FF и должен выглядеть как таблица u16
    chunk = dec[s:s + 0xc6c00]
    nz = sum(1 for b in chunk[:0x1000] if b not in (0, 0xff))
    cand.append((s, nz, pos))
print('кандидатов с запасом 0xC6C00:', len(cand))
for s, nz, pos in cand[:60]:
    head = dec[s:s + 16].hex()
    print(f'  start={s:#x} pos={pos:#x} nz1k={nz} head={head}')
# отдельно: рядом с известными FFLZ-блоками?
