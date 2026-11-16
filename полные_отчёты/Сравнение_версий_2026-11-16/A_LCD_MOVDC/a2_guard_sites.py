# -*- coding: utf-8 -*-
"""Шаг 2: точные адреса guard-проверки во всех 6 прошивках.

Для каждой модели/состояния дизассемблируем окно вокруг известных guard-адресов
и находим adrp/ldr пары, читающие глобальный флаг.
"""
import sys, os
sys.path.insert(0, r'<корень проекта>\Анализ_прошивки\Сравнение_версий_2026-11-16')
from fwcommon import *  # noqa

# известные/предполагаемые guard-адреса (X-H2 — из КОНТЕКСТ.md)
GUARDS = {
    ('X-H2', 'old'): 0x3107810,
    ('X-H2', 'new'): 0x310420c,
    ('X-H2S', 'old'): 0x341ac2c,
    ('X-H2S', 'new'): 0x341ac2c,
    ('X-T5', 'old'): 0x3046af0,
    ('X-T5', 'new'): 0x3046af0,
}

for m in MODELS:
    for st in ('old', 'new'):
        b = load(m, st, 1)
        va = GUARDS[(m, st)]
        s = func_start(b, va)
        print(f'===== {m} {st}: guard~{va:#x} func_start={s and hex(s)}')
        print(dis(b, va - 0x40, 40))
        print()
