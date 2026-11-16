# -*- coding: utf-8 -*-
"""Шаг 5 (v8): что ещё изменилось в коде модуля pm_dec (быстро).

Нормализация PC-относительных полей (BL/B, b.cond, cbz/cbnz, tbz/tbnz,
adr/adrp, ldr literal и ADD сразу после ADRP) — иначе перекомпоновка чужих
модулей даёт тысячи ложных «различий».

Проверяются два окна кода модуля (для каждой модели):
  A) код непосредственно ПЕРЕД helper  (там же соседние функции pm_dec);
  B) код ПОСЛЕ completion (сдвиг 0x1b4).
Внутри трёх исправленных функций сравнение не имеет смысла (они переписаны;
их разбор — в c1/c6).

Ожидаемый (и полученный) результат: все расхождения в A — обращения к ЧУЖОЙ
структуре, сдвинутой на +0x10 (0xe98->0xea8, 0x420->0x430, 0x118->0x128 …),
в B — единичные переходы в другие, переехавшие модули. Логика pm_dec за
пределами трёх функций не менялась.

Запуск: python c5_module_diff.py  (секунды)
Пишет: c5_diff.json, c5_out.txt
"""
import sys, os, json
import numpy as np
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from c_common import *  # noqa

HERE = os.path.dirname(os.path.abspath(__file__))
ANCH = {
    'X-H2':  {'old': (0x8fda98, 0x8fdc20, 0x8fdf68), 'new': (0x8fda98, 0x8fdcd8, 0x8fe0d8),
              'pre': (0x8f9c00, 0x8fda98), 'tail': (0x8ff000, 0x900000)},
    'X-H2S': {'old': (0x8f0d30, 0x8f0eb8, 0x8f1200), 'new': (0x8f0d30, 0x8f0f70, 0x8f1370),
              'pre': (0x8f0000, 0x8f0d30), 'tail': (0x8f1ac0, 0x8f3000)},
    'X-T5':  {'old': (0x8a2848, 0x8a29d0, 0x8a2d18), 'new': (0x8a2848, 0x8a2a88, 0x8a2e88),
              'pre': (0x8a1000, 0x8a2848), 'tail': (0x8a3600, 0x8a5000)},
}
TAIL_DELTA = 0x1b4

M_BR, V_BR = 0x7C000000, 0x14000000
M_BC, V_BC = 0xFF000010, 0x54000000
M_CB, V_CB = 0x7E000000, 0x34000000
V_TB = 0x36000000
M_ADRP, V_ADRP, V_ADR = 0x9F000000, 0x90000000, 0x10000000
M_LDRL, V_LDRL = 0x3B000000, 0x18000000
M_ADD, V_ADD = 0x7F200000, 0x11000000


def canon(ws):
    res = ws.copy()
    n = len(ws)
    adrp_reg = -1
    for i in range(n):
        w = int(ws[i])
        if (w & M_BR) == V_BR:
            res[i] = w & 0xFC000000
        elif (w & M_BC) == V_BC:
            res[i] = w & 0xFF00001F
        elif (w & M_CB) == V_CB:
            res[i] = w & 0xFF00001F
        elif (w & M_CB) == V_TB:
            res[i] = w & 0xFFF8001F
        elif (w & M_ADRP) == V_ADRP:
            res[i] = w & 0x9F00001F
            adrp_reg = w & 31
        elif (w & M_ADRP) == V_ADR:
            res[i] = w & 0x9F00001F
            adrp_reg = -1
        elif (w & M_LDRL) == V_LDRL:
            res[i] = w & 0xFF00001F
        elif adrp_reg >= 0 and (w & M_ADD) == V_ADD:
            rd, rn = w & 31, (w >> 5) & 31
            if rd == adrp_reg and rn == adrp_reg:
                res[i] = w & ~(0xFFF << 10)
            adrp_reg = -1
        else:
            adrp_reg = -1
    return res


def words(b):
    n = len(b.data) // 4
    return canon(np.frombuffer(b.data[:n * 4], dtype='<u4').astype(np.uint32))


def check(ao, an, lo, hi, d, bo, bn, limit=25):
    a = ao[lo // 4:hi // 4]
    b = an[(lo + d) // 4:(hi + d) // 4]
    n = min(len(a), len(b))
    idx = np.nonzero(a[:n] != b[:n])[0]
    rows = []
    for k in idx[:limit]:
        va = lo + int(k) * 4
        rows.append({'site': hex(va),
                     'old': f'{bo.u32(va):#010x} {dis(bo, va, 1).split(chr(58), 1)[-1].strip()}',
                     'new': f'{bn.u32(va + d):#010x} {dis(bn, va + d, 1).split(chr(58), 1)[-1].strip()}'})
    return {'words': n, 'mismatch': int(len(idx)), 'rows': rows}


def main():
    out = {}
    for m in MODELS:
        bo, bn = load(m, 'old', 2), load(m, 'new', 2)
        ao, an = words(bo), words(bn)
        A = ANCH[m]
        pre = check(ao, an, A['pre'][0], A['pre'][1], 0, bo, bn)
        tail = check(ao, an, A['tail'][0], A['tail'][1], TAIL_DELTA, bo, bn)
        print(f'===== {m}: helper {A["old"][0]:#x}->{A["new"][0]:#x}, '
              f'prepare {A["old"][1]:#x}->{A["new"][1]:#x}, '
              f'completion {A["old"][2]:#x}->{A["new"][2]:#x}')
        print(f"   окно перед helper {A['pre'][0]:#x}..{A['pre'][1]:#x} (delta 0): "
              f"слов {pre['words']}, расхождений {pre['mismatch']}")
        for r in pre['rows'][:8]:
            print(f"      {r['site']}: old `{r['old']}` | new `{r['new']}`")
        print(f"   окно после completion {A['tail'][0]:#x}..{A['tail'][1]:#x} "
              f"(delta {TAIL_DELTA:#x}): слов {tail['words']}, расхождений {tail['mismatch']}")
        for r in tail['rows'][:8]:
            print(f"      {r['site']}: old `{r['old']}` | new `{r['new']}`")
        out[m] = {'changed_functions': {
                      'helper': {'old': hex(A['old'][0]), 'new': hex(A['new'][0])},
                      'prepare': {'old': hex(A['old'][1]), 'new': hex(A['new'][1])},
                      'completion': {'old': hex(A['old'][2]), 'new': hex(A['new'][2])}},
                  'pre_helper_window': {'range': [hex(A['pre'][0]), hex(A['pre'][1])], **pre},
                  'tail_window': {'range': [hex(A['tail'][0]), hex(A['tail'][1])],
                                  'delta': hex(TAIL_DELTA), **tail}}
    open(os.path.join(HERE, 'c5_diff.json'), 'w', encoding='utf8').write(
        json.dumps(out, ensure_ascii=False, indent=1))


if __name__ == '__main__':
    main()
