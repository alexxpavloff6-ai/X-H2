"""F3: все записи в [#0x3978] в блоках 0/1 X-H2 5.33 и их источники.

Печатаем: адрес, функцию, инструкцию, последний mov/ldr в регистр-источник,
а также константу, если она есть. Цель — найти путь, который кладёт 0x2C (HDR).
"""
import sys, re, struct, collections
sys.path.insert(0, '<корень проекта>/Анализ_прошивки/Сравнение_версий_2026-11-16/F_режим_съёмки')
from fhelp import *

for idx in (0, 1):
    b = load('X-H2', 'new', idx)
    print(f'==== b{idx} ({b.version})')
    n = 0
    for va, w in iter_words(b):
        ins = insns(b, va, 1)
        if not ins:
            continue
        x = ins[0]
        if not (x.mnemonic == 'str' and re.fullmatch(r'w\d+, \[x\d+, #0x3978\]', x.op_str)):
            continue
        n += 1
        src = x.op_str.split(',')[0]
        fs, fe = func_range(b, va, 0x8000)
        # ищем источник: последняя запись в src в пределах 20 инструкций
        info = None
        for y in insns(b, max(b.base, va - 20 * 4), 26):
            if y.address >= va:
                break
            if y.mnemonic == 'mov' and y.op_str.startswith(src + ', #'):
                m = re.fullmatch(rf'{re.escape(src)}, #(0x[0-9a-f]+|\d+)', y.op_str)
                if m:
                    info = ('mov', int(m.group(1), 0), y.address, f'{y.mnemonic} {y.op_str}')
            elif y.mnemonic == 'ldr' and y.op_str.startswith(src + ', ['):
                info = ('ldr', None, y.address, f'{y.mnemonic} {y.op_str}')
            elif y.mnemonic == 'mov' and y.op_str.startswith(src + ', '):
                info = ('movreg', None, y.address, f'{y.mnemonic} {y.op_str}')
        mark = ''
        if info and info[0] == 'mov' and info[1] in (0x2c, 0x2d):
            mark = '  <== РЕЖИМ 0x2C/0x2D'
        print(f'  {va:x} (func {fs:#x}): {x.mnemonic} {x.op_str}   src={src} <- {info}{mark}')
        if info and info[0] == 'ldr':
            print('      ' + dis(b, info[2] - 12, 5).replace('\n', ' ; '))
    print(f'  всего записей: {n}')
