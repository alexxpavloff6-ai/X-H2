"""F2: что за значения пишутся в slot_rec+0x26c.

Для каждого `str/strb/strh [#0x26c]` ищем источник: последний mov/ldr в регистр-
источник перед записью; печатаем константу, если она в «режимном» наборе
(0x1d..0x24, 0x2c, 0x2d) и просто все константы для обзора.
"""
import sys, re, struct, collections
sys.path.insert(0, '<корень проекта>/Анализ_прошивки/Сравнение_версий_2026-11-16/F_режим_съёмки')
from fhelp import *

MODE = {0x1d, 0x1e, 0x1f, 0x20, 0x21, 0x22, 0x23, 0x24, 0x2c, 0x2d}
for idx in (0, 1):
    b = load('X-H2', 'new', idx)
    print(f'==== b{idx}')
    consts = collections.Counter()
    for va, w in iter_words(b):
        ins = insns(b, va, 1)
        if not ins:
            continue
        x = ins[0]
        if not (x.mnemonic.startswith('st') and re.fullmatch(r'\w+, \[x\d+, #0x26c\]', x.op_str)):
            continue
        src = x.op_str.split(',')[0]
        val = None
        txt = []
        for y in insns(b, max(b.base, va - 12 * 4), 14):
            txt.append(f'{y.mnemonic} {y.op_str}')
            if y.mnemonic == 'mov' and y.op_str.startswith(src + ', #'):
                m = re.fullmatch(rf'{re.escape(src)}, #(0x[0-9a-f]+|\d+)', y.op_str)
                if m:
                    val = int(m.group(1), 0)
        if val is not None:
            consts[val] += 1
        mark = ' <== РЕЖИМ' if val in MODE else ''
        print(f'  {va:x}: {x.mnemonic} {x.op_str}  src={src} const={val if val is not None else "?"}{mark}')
    print('  константы:', {hex(k): v for k, v in sorted(consts.items())})
