# -*- coding: utf-8 -*-
"""E16: все вызовы сеттеров свойств (семейство) и поиск рядом (в пределах ±60 insn)
имм. 0x2c либо 0x2b9, либо чтения id из памяти/таблицы.
"""
import sys, re, struct
sys.path.insert(0, r'<корень проекта>\Анализ_прошивки\Сравнение_версий_2026-11-16\E_сеттер_0x2B9')
from ecommon import *  # noqa

MODEL, STATE = 'X-H2', 'new'
SETTERS = {
    0x11335c4: 'set_nolock', 0x11335d8: 'set_lock', 0x11336dc: 'raw', 0x1133860: 'autoflag',
    0x1133628: 'set_array', 0x1133614: 'set_?', 0x12aa680: 'impl_nolock', 0x12aa71c: 'impl_lock',
    0x11e6bf0: 'dispatcher', 0x1135930: 'set2',
}

for idx in (0, 1):
    b = load(MODEL, STATE, idx)
    print(f'\n######## блок {idx} ########')
    total = 0
    for tgt, name in SETTERS.items():
        calls = [a for a, k in bl_callers(b, tgt) if k == 'bl']
        total += len(calls)
        print(f'  {name} {tgt:#x}: {len(calls)} вызовов')
    print('итого вызовов сеттеров:', total)

    # для каждого вызова — окно ±60 инструкций, ищем #0x2c / #0x2b9
    print('\n--- вызовы с имм. 0x2c или 0x2b9 в окне ±60 инструкций ---')
    for tgt, name in SETTERS.items():
        for a, k in bl_callers(b, tgt):
            if k != 'bl':
                continue
            win = [x for x in all_insns(b, a - 0xf0, a + 0x30) if x.mnemonic != '.byte']
            has2c = [(x.address, f'{x.mnemonic} {x.op_str}') for x in win
                     if re.search(r'#0x2c\b', x.op_str) or re.search(r', #0x2c$', x.op_str)]
            has2b9 = [(x.address, f'{x.mnemonic} {x.op_str}') for x in win
                      if re.search(r'#0x2b9\b', x.op_str)]
            if has2c or has2b9:
                print(f'\n  {name} {tgt:#x} <- {a:#x}  2b9:{len(has2b9)} 2c:{len(has2c)}')
                if has2b9:
                    print('     2b9:', [(hex(x), t) for x, t in has2b9])
                if has2c:
                    print('     2c :', [(hex(x), t) for x, t in has2c])
