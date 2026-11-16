"""F: какие страницы ADRP в диапазоне 0x2400000..0x2500000 существуют в каждой версии.

Нужно понять, сдвинулись ли глобалы 0x244eb20/0x244ebd4 в 5.30 / H2S / T5,
или у них другая раскладка RAM.
"""
import sys, re, json, struct, collections
sys.path.insert(0, r'<корень проекта>\Анализ_прошивки\Сравнение_версий_2026-11-16')
from fwcommon import *
import fwcommon


def pages(b, lo, hi):
    c = collections.Counter()
    for va, w in iter_words(b):
        if (w & 0x9f000000) == 0x90000000:
            t = fwcommon._adrp_target(w, va)
            if t and lo <= t[0] < hi:
                c[t[0]] += 1
    return c


for model in MODELS:
    for state in ('old', 'new'):
        for idx in (0, 1):
            b = load(model, state, idx)
            c = pages(b, 0x2400000, 0x2500000)
            if c:
                top = ' '.join(f'{p:#x}:{n}' for p, n in sorted(c.items()))
                print(f'{model} {b.version} b{idx}: {len(c)} pages | {top}')
