"""F: карта четырёх обработчиков (X-H2 5.33 b1): события, свойства, глобалы.

Для функций 0x2b47840 / 0x2b47bb8 / 0x2b47dd8 / 0x2b481ec перечисляем:
  * отправки кодов: mov w0,#code; bl 0x2c116ac (notify) / 0x2c35238 (dispatch);
  * чтения свойств: mov w0,#id; bl 0x11335ec / 0x1135930;
  * чтения/сравнения глобалов S (0x244eb20 и соседи) и системного контекста.
"""
import sys, re, json, struct, collections
sys.path.insert(0, '<корень проекта>/Анализ_прошивки/Сравнение_версий_2026-11-16/F_режим_съёмки')
from fhelp import *

FUNCS = [(0x2b47840, 'A: case 4/6/7/0x15 -> 0x358'),
         (0x2b47bb8, 'B: то же (дубль)'),
         (0x2b47dd8, 'C: кнопка/событие 0x29'),
         (0x2b481ec, 'D: ещё один путь')]

b = load('X-H2', 'new', 1)
SEND = {0x2c116ac, 0x2c35238, 0x2c35124, 0x2d3a500}
PROP = {0x11335ec: 'get', 0x1135930: 'check', 0x11335c4: 'set-default'}

for fs, title in FUNCS:
    fe = None
    for k in range(fs + 4, fs + 0x3000, 4):
        w = b.u32(k)
        if (w & 0xffc07fff) == 0xa9807bfd:
            fe = k
            break
    fe = fe or fs + 0x3000
    print(f'==== {title}: {fs:#x}..{fe:#x}')
    xs = insns(b, fs, (fe - fs) // 4)
    last_mov = {}
    for i, x in enumerate(xs):
        if x.mnemonic == 'mov' and x.op_str.startswith('w0, #'):
            m = re.fullmatch(r'w0, #(0x[0-9a-f]+|\d+)', x.op_str)
            if m:
                last_mov[x.address] = int(m.group(1), 0)
        if x.mnemonic == 'bl':
            tgt = int(x.op_str.split('#')[1], 0)
            prev = xs[i - 1] if i else None
            code = None
            if prev and prev.mnemonic == 'mov' and prev.op_str.startswith('w0, #'):
                code = int(re.search(r'#(0x[0-9a-f]+|\d+)', prev.op_str).group(1), 0)
            if not code:
                for back in range(i - 1, max(-1, i - 5), -1):
                    y = xs[back]
                    if y.mnemonic == 'mov' and y.op_str.startswith('w0, #'):
                        code = int(re.search(r'#(0x[0-9a-f]+|\d+)', y.op_str).group(1), 0)
                        break
            if tgt in SEND:
                print(f'   {x.address:x}: SEND code={code:#x} via {tgt:#x}')
            elif tgt in PROP:
                print(f'   {x.address:x}: PROP {PROP[tgt]} id={code:#x}')
    # глобалы: adrp 0x244e/0x244f + offset
    print('   -- чтения глобалов --')
    for va, w in iter_words(b):
        if not (fs <= va < fe):
            continue
        if (w & 0x9f000000) == 0x90000000:
            pass
    for x in xs:
        if x.mnemonic == 'adrp':
            page = int(x.op_str.split('#')[1], 0)
            reg = x.op_str.split(',')[0]
            for y in insns(b, x.address + 4, 2):
                m = re.fullmatch(r'(x\d+), (x\d+), #(-?0x[0-9a-f]+|-?\d+)', y.op_str)
                if y.mnemonic == 'add' and m and m.group(2) == reg:
                    t = page + int(m.group(3), 0)
                    if 0x2440000 <= t < 0x2470000:
                        print(f'   {y.address:x}: GLOBAL {t:#x}')
                    break
