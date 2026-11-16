# -*- coding: utf-8 -*-
"""E46: резолвер MODE_RECORD -> строка (блок 0) в трёх моделях.
Для значений 0x21..0x24, 0x2C, 0x2D находим cmp w0,#imm; b.eq body; в body — adrp/add
на строку и печатаем её."""
import sys, re
sys.path.insert(0, r'<корень проекта>\Анализ_прошивки\Сравнение_версий_2026-11-16\E_сеттер_0x2B9')
from ecommon import *  # noqa

CASES = (0x21, 0x22, 0x23, 0x24, 0x2C, 0x2D)


def resolve_body(b, body):
    page = None
    for x in insns(b, body, 3):
        if x.mnemonic == 'adrp':
            page = int(x.op_str.split('#')[1], 0)
        elif x.mnemonic == 'add' and page is not None and re.match(r'x0, x0, #', x.op_str):
            return page + int(x.op_str.split('#')[-1], 0)
        elif x.mnemonic in ('ret', 'b'):
            break
    return None


def scan(b, start_va, name, window=0x400):
    print(f'\n##### {name} {b.version} (блок 0), резолвер около {start_va:#x}')
    ins = [x for x in all_insns(b, start_va - 0x40, start_va + window) if x.mnemonic != '.byte']
    found = {}
    for i, x in enumerate(ins):
        if x.mnemonic == 'cmp' and re.match(r'w0, #', x.op_str):
            imm = int(x.op_str.split('#')[1], 0)
            if imm not in CASES or imm in found:
                continue
            nxt = ins[i + 1] if i + 1 < len(ins) else None
            if nxt and nxt.mnemonic == 'b.eq':
                tgt = int(nxt.op_str.strip('#'), 16)
                p = resolve_body(b, tgt)
                s = b.cstr(p, 80) if p else None
                found[imm] = (tgt, p, s)
    for imm in CASES:
        if imm in found:
            tgt, p, s = found[imm]
            print(f'  {imm:#04x}: body {tgt:#x} -> {p and hex(p)}  {s!r}')
        else:
            print(f'  {imm:#04x}: не найдено в окне')


scan(load('X-H2', 'new', 0), 0x1141ee0, 'X-H2')
scan(load('X-H2S', 'new', 0), 0x1461ae0, 'X-H2S')
scan(load('X-T5', 'new', 0), 0x114204c, 'X-T5')
