"""F3: писатели поля +0x7d0 (источник [ctx+0x3978] в пути проявки, 0x2e96014).

Сканируем блоки 0/1 X-H2 5.33 на `str/strh/strb ... [#0x7d0]`; печатаем функцию,
контекст (что кладётся) и ищем константы 0x2C/0x1d..0x24.
"""
import sys, re, struct, collections
sys.path.insert(0, '<корень проекта>/Анализ_прошивки/Сравнение_версий_2026-11-16/F_режим_съёмки')
from fhelp import *

MODE = {0x1d, 0x1e, 0x1f, 0x20, 0x21, 0x22, 0x23, 0x24, 0x2c, 0x2d}
for idx in (0, 1):
    b = load('X-H2', 'new', idx)
    print(f'==== b{idx} ({b.version})')
    n = 0
    for va, w in iter_words(b):
        ins = insns(b, va, 1)
        if not ins:
            continue
        x = ins[0]
        if not x.mnemonic.startswith('st'):
            continue
        if not re.fullmatch(r'\w+, \[x\d+, #0x7d0\]', x.op_str):
            continue
        n += 1
        src = x.op_str.split(',')[0]
        fs, fe = func_range(b, va, 0x6000)
        # значение источника: последний mov в src
        val = None
        ctx = list(insns(b, max(b.base, va - 12 * 4), 14))
        for y in ctx:
            if y.mnemonic == 'mov' and y.op_str.startswith(src + ', #'):
                m = re.fullmatch(rf'{re.escape(src)}, #(0x[0-9a-f]+|\d+)', y.op_str)
                if m:
                    val = int(m.group(1), 0)
        mark = ' <== РЕЖИМ' if val in MODE else ''
        print(f'  {va:x} (func {fs:#x}): {x.mnemonic} {x.op_str}  const={val if val is not None else "?"}{mark}')
        print('     ' + ' ; '.join(f'{y.mnemonic} {y.op_str}' for y in ctx[-8:]))
    print(f'  всего записей [#0x7d0]: {n}')
