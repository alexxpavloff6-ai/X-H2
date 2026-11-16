"""F2: писатели поля +0x26c записи слота (0x229a3a0 + n*0x2748) —
именно оно попадает в job+0x144 → [ctx+0x3978].

Ищем:
  1) вызовы сеттера 0x155ac14 (w0=record ptr, w1=значение);
  2) прямые `str/strb [#0x26c]` в блоках 0/1;
  3) для каждого сайта — константа/источник значения и функция.
"""
import sys, re, struct, collections
sys.path.insert(0, '<корень проекта>/Анализ_прошивки/Сравнение_версий_2026-11-16/F_режим_съёмки')
from fhelp import *

for idx in (0, 1):
    b = load('X-H2', 'new', idx)
    print(f'==== b{idx} ({b.version})')
    c = bl_callers(b, 0x155ac14)
    print(f'вызовов сеттера 0x155ac14: {len(c)}, сайты {[hex(a) for a,_ in c][:20]}')
    for a, _ in c[:12]:
        print(f'  --- {a:x}')
        print(dis(b, a - 16, 12).replace('\n', '\n      '))
    print('-- прямые записи [#0x26c] --')
    n = 0
    for va, w in iter_words(b):
        ins = insns(b, va, 1)
        if not ins:
            continue
        x = ins[0]
        if x.mnemonic.startswith('st') and re.fullmatch(r'\w+, \[x\d+, #0x26c\]', x.op_str):
            n += 1
            fs, fe = func_range(b, va, 0x4000)
            print(f'  {va:x} (func {fs:x}): {x.mnemonic} {x.op_str}')
    print(f'  всего: {n}')
