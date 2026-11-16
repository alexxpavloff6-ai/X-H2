# -*- coding: utf-8 -*-
"""Шаг 8: контекст писателей флага (str w2,[x,#0x43c/0x434]).

Для каждого писателя: старт функции (эвристика+проверка), 50 инструкций ДО
и 30 ПОСЛЕ, отдельно расшифровка, откуда берётся w2 (mov/csel/and/... ).
Также ищем callers функции-писателя (bl_callers).
"""
import sys, os, json, struct
sys.path.insert(0, r'<корень проекта>\Анализ_прошивки\Сравнение_версий_2026-11-16')
from fwcommon import *  # noqa

HERE = os.path.dirname(os.path.abspath(__file__))
WRITERS = {
    ('X-H2', 'old'): [0x31085a8, 0x3108aa8],
    ('X-H2', 'new'): [0x3104728, 0x3104c40],
    ('X-H2S', 'old'): [0x341afb8, 0x341b4a0],
    ('X-H2S', 'new'): [0x341b138, 0x341b638],
    ('X-T5', 'old'): [0x3046e6c, 0x304736c],
    ('X-T5', 'new'): [0x304700c, 0x3047524],
}


def main():
    for m in MODELS:
        for st in ('old', 'new'):
            b = load(m, st, 1)
            for wva in WRITERS[(m, st)]:
                s = func_start(b, wva)
                print(f'===== {m} {st} writer@{wva:#x} func_start={s and hex(s)}')
                lo = (s or wva - 0x200)
                print(dis(b, lo, (wva - lo) // 4 + 24))
                if s:
                    callers = bl_callers(b, s)
                    print('  callers:', [(hex(a), k) for a, k in callers])
                print()


if __name__ == '__main__':
    main()
