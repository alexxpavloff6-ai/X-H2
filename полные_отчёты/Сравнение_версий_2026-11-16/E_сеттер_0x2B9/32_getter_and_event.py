# -*- coding: utf-8 -*-
"""E32: проверки для отчёта.
(1) Геттер-диспетчер 0x12aa788, таблица 0x1745e70 (база 0x12aa7dc): id 0x2b9 -> чанк,
    чанк должен читать settings+0x144.
(2) Событие 0x358 -> id 0x2b9: jump-таблица 0x33BD468 (группа 0x300, база 0x2d3a94c),
    тело для кода 0x358 должно класть w19=0x2b9.
"""
import sys, struct
sys.path.insert(0, r'<корень проекта>\Анализ_прошивки\Сравнение_версий_2026-11-16\E_сеттер_0x2B9')
from ecommon import *  # noqa

b0 = load('X-H2', 'new', 0)
b1 = load('X-H2', 'new', 1)

print('=== (1) геттер-диспетчер 0x12aa788 (таблица u32 0x1745e70, база 0x12aa7dc) ===')
TAB, BASE = 0x1745e70, 0x12aa7dc
for idv in (0x2b9, 0x2b8, 0x2a1):
    v = u32(b0, TAB + 4 * (idv - 1))
    sv = v - (1 << 32) if v & 0x80000000 else v
    t = BASE + sv * 4
    print(f'  id {idv:#x} -> {t:#x}')
    dump_range(b0, t, t + 0x70)

print('\n=== (2) событие 0x358 -> id свойства (jump-таблица 0x33bd468) ===')
TAB2 = 0x33bd468
base2 = 0x2d3a94c
for code in (0x357, 0x358, 0x359, 0x35a):
    idx = code - 0x300
    off = u16(b1, TAB2 + 2 * idx)
    so = off - (1 << 16) if off & 0x8000 else off
    t = base2 + so * 4
    print(f'  код {code:#x}: offset {off:#x} -> тело {t:#x}')
    dump_range(b1, t, t + 0x14)
