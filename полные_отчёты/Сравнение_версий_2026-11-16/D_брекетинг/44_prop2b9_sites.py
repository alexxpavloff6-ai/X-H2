# -*- coding: utf-8 -*-
"""D5: кто пишет свойство 0x2B9 (код режима) и какое значение.

Находим все `mov w0,#0x2b9` в блоках 0/1/2 (movz w0,#0x2b9), печатаем контекст
(значение w1, целевая функция bl, ближайшие строки) — чтобы отделить геттеры от
сеттеров и найти путь, который пишет 0x2C.
"""
import sys, re, struct
sys.path.insert(0, r'<корень проекта>\Анализ_прошивки\Сравнение_версий_2026-11-16\D_брекетинг')
from dhelp import *  # noqa

def decode(raw):
    for enc in ('shift_jis', 'cp932'):
        try:
            return raw.decode(enc)
        except Exception:
            pass
    return raw.decode('latin1')

def nearby_strings(b, lo, hi, limit=8):
    out = []
    ins = [x for x in all_insns(b, lo, hi) if x.mnemonic != '.byte']
    for i, x in enumerate(ins):
        if x.mnemonic != 'adrp':
            continue
        page = int(x.op_str.split('#')[1], 0)
        reg = x.op_str.split(',')[0]
        for y in ins[i + 1:i + 3]:
            if y.mnemonic == 'add' and y.op_str.startswith(reg + ', '):
                off = int(y.op_str.split('#')[1], 0)
                o2 = b.off(page + off)
                if 0 <= o2 < len(b.data):
                    raw = b.data[o2:o2 + 70].split(b'\x00')[0]
                    if raw and len(raw) >= 4:
                        s = decode(raw)
                        if all(32 <= ord(c) < 127 or ord(c) > 0x2000 for c in s):
                            out.append(s)
                break
    return out[:limit]

M = 0x52800000 | (0x2b9 << 5)     # mov w0,#0x2b9
M1 = M | 1                        # mov w1,#0x2b9

for model, state in (('X-H2', 'new'), ('X-H2', 'old')):
    for idx in (0, 1, 2):
        b = load(model, state, idx)
        d = b.data
        for o in range(0, len(d) - 8, 4):
            w = struct.unpack_from('<I', d, o)[0]
            if w not in (M, M1):
                continue
            va = b.base + o
            print(f'\n=== {model} {state} b{idx} {va:#x} ===')
            print(dis(b, va - 0x18, 14).replace('\n', '\n   '))
            ss = nearby_strings(b, va - 0x80, va + 0x120)
            if ss:
                print('   строки:', ss)
