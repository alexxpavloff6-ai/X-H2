# -*- coding: utf-8 -*-
"""Q3 шаг 4: найти истинную базу блока 2. Резолвер возвращает -0x32 (movn w0,#0x31).
Ищем все такие сайты в блоке 2 и проверяем, какой из них — резолвер записей
(вызывается из геттера 0x14CF354 как VA 0x5460C)."""
import struct
import sys
from pathlib import Path

HERE = Path(__file__).resolve().parent
sys.path.insert(0, str(HERE.parents[1] / 'Сравнение_версий_2026-11-16'))
from fwcommon import load, dis, insns, func_start  # noqa: E402

b2 = load('X-H2', 'old', 2)
# movn w0, #0x31  => 0x12800620 ; также movn w19/w20 etc варианты rd
targets = []
for o in range(0, len(b2.data) - 3, 4):
    w = struct.unpack_from('<I', b2.data, o)[0]
    if (w & 0xFFFFFFE0) == 0x12800620:  # movn w<rd>, #0x31  (= -0x32)
        targets.append(o)

print('movn w?,#0x31 (-0x32) сайтов в блоке 2:', len(targets))
rows = []
for o in targets:
    fs = func_start(b2, o)
    rows.append((o, fs))
# уникальные функции
funcs = sorted(set(fs for _, fs in rows if fs))
print('уникальных функций:', len(funcs))
for fs in funcs:
    print(f'--- функция file_off={fs:#x} (если база B2, то VA={fs:#x}+B2) ---')
    print(dis(b2, fs, 24))
    print()
