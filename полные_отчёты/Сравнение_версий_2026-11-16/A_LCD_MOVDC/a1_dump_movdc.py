# -*- coding: utf-8 -*-
"""Шаг 1: найти и распечатать MOVDC-функцию old/new для трёх моделей.

Использование:  python a1_dump_movdc.py [--full]
Пишет a1_movdc_<model>_<state>.txt рядом с собой.
"""
import sys, os
sys.path.insert(0, r'<корень проекта>\Анализ_прошивки\Сравнение_версий_2026-11-16')
from fwcommon import *  # noqa

HERE = os.path.dirname(os.path.abspath(__file__))

# точки входа / якоря из КОНТЕКСТ.md (X-H2 old -> new)
ANCHORS = {
    'X-H2':  {'old': 0x3107e84, 'new': 0x3103ff8},
    'X-H2S': {'old': 0x341a638, 'new': 0x341a638},   # уточняется ниже
    'X-T5':  {'old': 0x30464fc, 'new': 0x30464fc},   # уточняется ниже
}


def find_movdc(b):
    """Ищем адрес строки 'MOVDC' и все adrp+add ссылки на неё."""
    hits = find_bytes(b, b'MOVDC\x00')
    rows = []
    for h in hits:
        rows.append((h, b.cstr(h)))
    return rows


def dump(model, state, va, n=0x400):
    b = load(model, state, 1)
    start = func_start(b, va)
    if start is None:
        start = va
    print(f'--- {model} {state} b1: anchor={va:#x} func_start={start:#x}')
    print(dis(b, start, n))


if __name__ == '__main__':
    print('=== строки MOVDC ===')
    for m in MODELS:
        for st in ('old', 'new'):
            b = load(m, st, 1)
            print(m, st, [(hex(a), s) for a, s in find_movdc(b)])
