# -*- coding: utf-8 -*-
"""Шаг 7: перекрёстная проверка к c5 — «изменены только три функции».

Для каждой модели считаются доли совпавших нормализованных слов в трёх зонах:
  1) окно кода ПЕРЕД helper   — ожидаем почти полное совпадение (delta 0);
  2) сами функции helper/prepare/completion — ожидаем НЕсовпадение
     (они переписаны), причём у prepare/completion со сдвигом +0xb8/+0x170;
  3) окно ПОСЛЕ completion    — ожидаем почти полное совпадение (delta 0x1b4).

Запуск: python c7_module_check.py  (пишет c7_module_check.json)
"""
import sys, os, json
import numpy as np
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from c_common import *  # noqa
from c5_module_diff import words, ANCH

HERE = os.path.dirname(os.path.abspath(__file__))
TAIL_DELTA = 0x1b4


def frac(ao, an, lo, hi, d):
    a = ao[lo // 4:hi // 4]
    b = an[(lo + d) // 4:(hi + d) // 4]
    n = min(len(a), len(b))
    if n == 0:
        return 0, 0, 0
    eq = int((a[:n] == b[:n]).sum())
    return n, eq, n - eq


def main():
    out = {}
    for m in MODELS:
        bo, bn = load(m, 'old', 2), load(m, 'new', 2)
        ao, an = words(bo), words(bn)
        A = ANCH[m]
        oh, op, oc = A['old']
        nh, np_, nc = A['new']
        zones = [
            ('код перед helper', A['pre'][0], A['pre'][1], 0, 'почти всё совпадает'),
            ('helper (переписан)', oh, op, nh - oh, 'не совпадает'),
            ('prepare (переписан)', op, oc, np_ - op, 'не совпадает'),
            ('completion (переписана)', oc, oc + 0x2c4, nc - oc, 'не совпадает'),
            ('код после completion', A['tail'][0], A['tail'][1], TAIL_DELTA, 'почти всё совпадает'),
        ]
        rec = []
        print('=====', m)
        for name, lo, hi, d, expect in zones:
            n, eq, ne = frac(ao, an, lo, hi, d)
            rec.append({'zone': name, 'old': hex(lo), 'old_end': hex(hi),
                        'delta': hex(d), 'words': n, 'equal': eq, 'mismatch': ne,
                        'equal_share': round(eq / n, 4) if n else None,
                        'expect': expect})
            print(f"   {name:28s} {lo:#08x}..{hi:#08x} delta {d:#06x}: "
                  f"слов {n}, совпало {eq} ({eq/n:.1%})" if n else '')
        out[m] = rec
    open(os.path.join(HERE, 'c7_module_check.json'), 'w', encoding='utf8').write(
        json.dumps(out, ensure_ascii=False, indent=1))


if __name__ == '__main__':
    main()
