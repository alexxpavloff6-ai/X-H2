# -*- coding: utf-8 -*-
"""Шаг 11: полный дамп MOVDC-функции с guard'ом (old/new), с расшифровкой строк лога.

X-H2 old func 0x31076b8, new 0x3103ff8.
Для каждой adrp+add, дающей указатель на строку в .rodata (0x3000000..0x3a00000),
печатаем содержимое строки.
Также сохраняем дампы a11_body_<model>_<state>.asm.
"""
import sys, os, json, struct
sys.path.insert(0, r'<корень проекта>\Анализ_прошивки\Сравнение_версий_2026-11-16')
from fwcommon import *  # noqa
import fwcommon

HERE = os.path.dirname(os.path.abspath(__file__))
FUNCS = {
    ('X-H2', 'old'): 0x31076b8,
    ('X-H2', 'new'): 0x3103ff8,
    ('X-H2S', 'old'): 0x341a89c,
    ('X-H2S', 'new'): 0x341aa10,
    ('X-T5', 'old'): 0x3046748,
    ('X-T5', 'new'): 0x30468dc,
}
N = 420


def annotate(b, va, n):
    """Дамп с пометками: adrp+add -> строка."""
    out = []
    xs = insns(b, va, n)
    i = 0
    while i < len(xs):
        x = xs[i]
        line = f'{x.address:x}: {x.mnemonic} {x.op_str}'
        if x.mnemonic == 'adrp' and i + 1 < len(xs):
            y = xs[i + 1]
            if y.mnemonic == 'add' and y.op_str.startswith(x.op_str.split(',')[0] + ','):
                try:
                    page = int(x.op_str.split('#')[1], 0)
                    imm = int(y.op_str.split('#')[1], 0)
                    s = b.cstr(page + imm)
                    if s:
                        line += f'   ; "{s}"'
                except (ValueError, IndexError):
                    pass
        # комментарий к guard-байтам
        out.append(line)
        i += 1
    return '\n'.join(out)


def main():
    for m in MODELS:
        for st in ('old', 'new'):
            b = load(m, st, 1)
            va = FUNCS[(m, st)]
            txt = annotate(b, va, N)
            path = os.path.join(HERE, f'a11_body_{m}_{st}.asm')
            open(path, 'w', encoding='utf8').write(txt)
            print(f'=== {m} {st} {va:#x} -> {path} ({len(txt.splitlines())} строк)')


if __name__ == '__main__':
    main()
