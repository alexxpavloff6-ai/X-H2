# -*- coding: utf-8 -*-
"""Шаг 12: извлечь MOVDC-функцию целиком (до эпилога add sp,sp,#0x2a0; ret)
и сравнить old/new (нормализуя адреса переходов).

Пишет a12_func_<model>_<state>.asm и печатает diff old->new.
"""
import sys, os, json, re, difflib
sys.path.insert(0, r'<корень проекта>\Анализ_прошивки\Сравнение_версий_2026-11-16')
from fwcommon import *  # noqa

HERE = os.path.dirname(os.path.abspath(__file__))
FUNCS = {
    'X-H2': (0x3107e84, 0x3103ff8),
    'X-H2S': (0x341a89c, 0x341aa10),
    'X-T5': (0x3046748, 0x30468dc),
}
MAXN = 4000


def extract(b, va):
    xs = insns(b, va, MAXN)
    out = []
    for i, x in enumerate(xs):
        out.append(x)
        if x.mnemonic == 'add' and x.op_str == 'sp, sp, #0x2a0':
            # ожидаем ldp x29,x30 / ldp .. / ret в пределах 3
            tail = ' '.join(y.mnemonic for y in xs[i + 1:i + 5])
            if 'ret' in tail:
                break
    return out


def norm(x):
    t = f'{x.mnemonic} {x.op_str}'
    # нормализуем цели переходов
    t = re.sub(r'#0x[0-9a-f]+', '#T', t)
    return t


def annotate(b, xs):
    lines = []
    for i, x in enumerate(xs):
        s = f'{x.address:x}: {x.mnemonic} {x.op_str}'
        if x.mnemonic == 'adrp' and i + 1 < len(xs):
            y = xs[i + 1]
            if y.mnemonic == 'add' and y.op_str.startswith(x.op_str.split(',')[0] + ','):
                try:
                    page = int(x.op_str.split('#')[1], 0)
                    imm = int(y.op_str.split('#')[1], 0)
                    st = b.cstr(page + imm)
                    if st:
                        s += f'   ; "{st}"'
                except (ValueError, IndexError):
                    pass
        lines.append(s)
    return lines


def main():
    for m in MODELS:
        olds, news = FUNCS[m]
        bo, bn = load(m, 'old', 1), load(m, 'new', 1)
        fo, fn = extract(bo, olds), extract(bn, news)
        print(f'=== {m}: old {olds:#x} ({len(fo)} инстр.)  new {news:#x} ({len(fn)} инстр.)')
        open(os.path.join(HERE, f'a12_func_{m}_old.asm'), 'w', encoding='utf8').write(
            '\n'.join(annotate(bo, fo)))
        open(os.path.join(HERE, f'a12_func_{m}_new.asm'), 'w', encoding='utf8').write(
            '\n'.join(annotate(bn, fn)))
        no = [norm(x) for x in fo]
        nn = [norm(x) for x in fn]
        sm = difflib.SequenceMatcher(None, no, nn, autojunk=False)
        for tag, i1, i2, j1, j2 in sm.get_opcodes():
            if tag == 'equal':
                continue
            print(f'  [{tag}] old[{i1}:{i2}] {fo[i1].address if i1 < len(fo) else 0:#x}..  '
                  f'new[{j1}:{j2}] {fn[j1].address if j1 < len(fn) else 0:#x}..')
            for x in fo[i1:i2]:
                print(f'    - {x.address:x}: {x.mnemonic} {x.op_str}')
            for x in fn[j1:j2]:
                print(f'    + {x.address:x}: {x.mnemonic} {x.op_str}')


if __name__ == '__main__':
    main()
