# -*- coding: utf-8 -*-
"""E9: общий API установки свойства: 0x11335c4, обёртки 0x11336dc/0x1133860,
0x1133818, и вызовы с нелитеральным id (w0 не mov #imm перед bl)."""
import sys, re, struct
sys.path.insert(0, r'<корень проекта>\Анализ_прошивки\Сравнение_версий_2026-11-16\E_сеттер_0x2B9')
from ecommon import *  # noqa

MODEL, STATE = 'X-H2', 'new'
b = load(MODEL, STATE, 0)

for f in (0x11335c4, 0x11335ec, 0x1133818, 0x11336dc, 0x1133860, 0x1137b0c):
    print(f'\n=== {f:#x} ===')
    st = find_prologue(b, f, limit=0x400)
    print('prologue:', hex(st) if st else None, ' callers:', len(bl_callers(b, st or f)))
    dump_range(b, st or f, (st or f) + 0xc0)

def callers_nonliteral(target, back=0x40, maxshow=40):
    out = []
    for a, k in bl_callers(b, target):
        if k != 'bl':
            continue
        # смотрим назад: задаётся ли w0 через mov w0,#imm
        hist = [x for x in all_insns(b, a - back, a) if x.mnemonic != '.byte']
        lit = None
        for y in reversed(hist):
            if y.mnemonic in ('mov', 'movz') and re.match(r'w0, #', y.op_str):
                lit = ('lit', int(y.op_str.split('#')[1], 0), y.address)
                break
            if y.mnemonic in ('mov', 'ldr', 'ldrb', 'ldrh', 'add', 'orr', 'and', 'bl', 'b', 'cbz', 'cbnz') and re.match(r'w0,', y.op_str):
                lit = ('dyn', y.mnemonic, y.address)
                break
        out.append((a, hist, lit))
    return out

for tgt in (0x11335c4, 0x11336dc, 0x1133860):
    rows = callers_nonliteral(tgt)
    dyn = [r for r in rows if r[2] and r[2][0] == 'dyn']
    print(f'\n=== {tgt:#x}: вызовов {len(rows)}, нелитеральный w0: {len(dyn)} ===')
    for a, hist, lit in rows[:200]:
        tag = 'LIT' if lit and lit[0] == 'lit' else 'DYN'
        print(f'  {a:#x} {tag} {lit}')
