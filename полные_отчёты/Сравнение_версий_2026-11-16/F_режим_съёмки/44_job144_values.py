"""F2: какие значения пишутся в job+0x144 (и +0x12c) — ищем константы режимов.

Для каждого `str/strb/strh [#0x144]` печатаем 8 предшествующих инструкций и
«последний mov/ldr в регистр-источник», чтобы увидеть константу (0x2c/0x2d/0x1d/0x20/0x21..0x24).
"""
import sys, re, struct, collections
sys.path.insert(0, '<корень проекта>/Анализ_прошивки/Сравнение_версий_2026-11-16/F_режим_съёмки')
from fhelp import *

b = load('X-H2', 'new', 1)
MODE_VALS = {0x1d, 0x1e, 0x1f, 0x20, 0x21, 0x22, 0x23, 0x24, 0x2c, 0x2d, 0x25, 0x26, 0x28}

sites = []
for va, w in iter_words(b):
    ins = insns(b, va, 1)
    if not ins:
        continue
    x = ins[0]
    if x.mnemonic.startswith('st') and re.fullmatch(r'\w+, \[x\d+, #0x144\]', x.op_str):
        sites.append((va, x))

print(f'записей [#0x144]: {len(sites)}')
interesting = 0
for va, x in sites:
    src = x.op_str.split(',')[0]
    ctx = list(insns(b, va - 8 * 4, 10))
    txt = ' ; '.join(f'{y.mnemonic} {y.op_str}' for y in ctx)
    val = None
    for y in ctx:
        if y.mnemonic == 'mov' and y.op_str.startswith(src + ', #'):
            m = re.fullmatch(rf'{re.escape(src)}, #(0x[0-9a-f]+|\d+)', y.op_str)
            if m:
                val = int(m.group(1), 0)
    tag = ''
    if val in MODE_VALS:
        tag = ' <== КОНСТАНТА РЕЖИМА'
        interesting += 1
    print(f'{va:x}: {x.mnemonic} {x.op_str}  (src {src}={val if val is not None else "?"}){tag}')
print(f'\nсайтов с константой из набора режимов: {interesting}')
