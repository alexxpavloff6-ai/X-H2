"""F: декодер линейной цепочки cmp/b.eq -> блок adrp+add+str -> b.

Для адреса-входа (например 0x1141ee0) собираем пары (значение -> строка),
пока идём по цепочке. Так получаем полные enum'ы MODE_* из b0.
"""
import sys, re
sys.path.insert(0, '<корень проекта>/Анализ_прошивки/Сравнение_версий_2026-11-16/F_режим_съёмки')
from fhelp import *


def block_string(b, target):
    """По адресу блока вернуть строку, которую он возвращает (adrp+add; b/ret)."""
    xs = insns(b, target, 4)
    if not xs:
        return None
    if xs[0].mnemonic != 'adrp':
        return None
    page = int(xs[0].op_str.split('#')[1], 0)
    reg = xs[0].op_str.split(',')[0]
    if len(xs) > 1 and xs[1].mnemonic == 'add':
        m = re.fullmatch(r'(x\d+), (x\d+), #(-?0x[0-9a-f]+|-?\d+)', xs[1].op_str)
        if m and m.group(2) == reg:
            return cstr2(b, page + int(m.group(3), 0))
    return None


def decode_chain(b, entry, maxn=200):
    out = []
    for x in insns(b, entry, maxn):
        s = x.op_str
        m = re.fullmatch(r'w\d+, #(-?0x[0-9a-f]+|-?\d+)', s)
        if x.mnemonic == 'cbz':
            t = int(s.split('#')[1], 0)
            out.append((0, block_string(b, t)))
            continue
        if m and x.mnemonic == 'cmp':
            v = int(m.group(1), 0)
            # следующая b.eq
            nxt = insns(b, x.address + 4, 1)
            if nxt and nxt[0].mnemonic == 'b.eq':
                t = int(nxt[0].op_str.split('#')[1], 0)
                out.append((v, block_string(b, t)))
            continue
        if x.mnemonic == 'csel':
            # последний элемент: cmp w0,#N; csel x0,x1,xzr,eq; b
            prev = insns(b, x.address - 4, 1)
            if prev and prev[0].mnemonic == 'cmp':
                v = int(re.search(r'#(-?0x[0-9a-f]+|-?\d+)', prev[0].op_str).group(1), 0)
                # x1 указывает на строку
                out.append((v, 'LAST_CANDIDATE'))
            break
        if x.mnemonic in ('ret', 'b') and x.mnemonic == 'b':
            break
    return out


b = load('X-H2', 'new', 0)
for entry in (0x1141ee0,):
    print(f'== entry {entry:#x}')
    for v, s in decode_chain(b, entry):
        print(f'   {v:#x} -> {s}')
