"""F2: читатели байта +0x26c (слот-запись 0x229a3a0+n*0x2748) и сравнения.

Ищем `ldr/ldrb wN,[xM,#0x26c]` и в пределах 12 инструкций `cmp wN,#imm`
(особенно 0x1d..0x24, 0x2c, 0x2d), а также `strb`-писателей с константами.
"""
import sys, re, struct, collections
sys.path.insert(0, '<корень проекта>/Анализ_прошивки/Сравнение_версий_2026-11-16/F_режим_съёмки')
from fhelp import *

MODE = {0x1d, 0x1e, 0x1f, 0x20, 0x21, 0x22, 0x23, 0x24, 0x2c, 0x2d}
for idx in (0, 1):
    b = load('X-H2', 'new', idx)
    print(f'==== b{idx}')
    for va, w in iter_words(b):
        ins = insns(b, va, 1)
        if not ins:
            continue
        x = ins[0]
        if x.mnemonic not in ('ldr', 'ldrb'):
            continue
        m = re.fullmatch(r'(w\d+), \[x\d+, #0x26c\]', x.op_str)
        if not m:
            continue
        dst = m.group(1)
        vals = set()
        for y in insns(b, va + 4, 12):
            mm = re.fullmatch(rf'{dst}, #(0x[0-9a-f]+|\d+)', y.op_str)
            if y.mnemonic == 'cmp' and mm:
                vals.add(int(mm.group(1), 0))
            if y.mnemonic in ('bl', 'b', 'ret'):
                break
        mark = ' <== режимы!' if vals & MODE else ''
        if vals:
            print(f'  {va:x}: ldr {x.op_str}  cmp {sorted(hex(v) for v in vals)}{mark}')
