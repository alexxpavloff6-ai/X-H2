# -*- coding: utf-8 -*-
"""Шаг 18: сравнить old/new функции «применения настроек» (те, что копируют флаг).

X-H2 old 0x3108494 -> new 0x3104614; H2S 0x341aea8 -> 0x341b028;
T5 0x3046d58 -> 0x3046ef8. Кадр 0x20 байт (add sp,sp,#0x20; ret).
"""
import sys, os, re, difflib
sys.path.insert(0, r'<корень проекта>\Анализ_прошивки\Сравнение_версий_2026-11-16')
from fwcommon import *  # noqa

FUNCS = {
    'X-H2': (0x3108494, 0x3104614, 0x20),
    'X-H2S': (0x341aea8, 0x341b028, 0x20),
    'X-T5': (0x3046d58, 0x3046ef8, 0x20),
}
HERE = os.path.dirname(os.path.abspath(__file__))


def extract(b, va, framesz):
    xs = insns(b, va, 2000)
    out = []
    for i, x in enumerate(xs):
        out.append(x)
        if x.mnemonic == 'add' and x.op_str == f'sp, sp, #{framesz:#x}':
            tail = ' '.join(y.mnemonic for y in xs[i + 1:i + 5])
            if 'ret' in tail:
                break
    return out


def norm(x):
    return re.sub(r'#0x[0-9a-f]+', '#T', f'{x.mnemonic} {x.op_str}')


if __name__ == '__main__':
    for m in MODELS:
        olds, news, fr = FUNCS[m]
        bo, bn = load(m, 'old', 1), load(m, 'new', 1)
        fo, fn = extract(bo, olds, fr), extract(bn, news, fr)
        print(f'=== {m}: old {olds:#x} ({len(fo)}) new {news:#x} ({len(fn)})')
        sm = difflib.SequenceMatcher(None, [norm(x) for x in fo], [norm(x) for x in fn],
                                     autojunk=False)
        for tag, i1, i2, j1, j2 in sm.get_opcodes():
            if tag == 'equal':
                continue
            print(f'  [{tag}] old[{i1}:{i2}] new[{j1}:{j2}]')
            for x in fo[i1:i2]:
                print(f'    - {x.address:x}: {x.mnemonic} {x.op_str}')
            for x in fn[j1:j2]:
                print(f'    + {x.address:x}: {x.mnemonic} {x.op_str}')
