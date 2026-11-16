# -*- coding: utf-8 -*-
"""D2: строки в функции-писателе флага 0xa8 и в вызывающих её функциях.

Печатает все строки (ASCII и Shift-JIS), на которые ссылается функция, а также
вызываемые адреса и их строки. Аргумент — модель/версия и адрес.
"""
import sys, re
sys.path.insert(0, r'<корень проекта>\Анализ_прошивки\Сравнение_версий_2026-11-16\D_брекетинг')
from dhelp import *  # noqa

def decode(raw):
    for enc in ('shift_jis', 'cp932', 'latin1'):
        try:
            return raw.decode(enc)
        except Exception:
            pass
    return repr(raw)

def starts_index(b):
    out = []
    for o in range(0, len(b.data) - 3, 4):
        w = struct.unpack_from('<I', b.data, o)[0]
        if (w & 0xffc07fff) == 0xa9807bfd:
            out.append(b.base + o)
    return out

def func_range(b, starts, addr):
    fs = max([s for s in starts if s <= addr], default=None)
    i = starts.index(fs)
    return fs, (starts[i + 1] if i + 1 < len(starts) else b.end)

def scan(b, lo, hi):
    strings, calls = [], []
    ins = [x for x in all_insns(b, lo, hi) if x.mnemonic != '.byte']
    for i, x in enumerate(ins):
        if x.mnemonic == 'adrp':
            page = int(x.op_str.split('#')[1], 0)
            reg = x.op_str.split(',')[0]
            for y in ins[i + 1:i + 3]:
                if y.mnemonic == 'add' and y.op_str.startswith(reg + ', '):
                    try:
                        off = int(y.op_str.split('#')[1], 0)
                    except Exception:
                        break
                    o2 = b.off(page + off)
                    if 0 <= o2 < len(b.data):
                        raw = b.data[o2:o2 + 96].split(b'\x00')[0]
                        if raw and not all(32 <= c < 127 for c in raw):
                            # Shift-JIS/UTF-16?
                            s = decode(raw)
                            if any(ord(ch) > 0x2000 for ch in s):
                                strings.append(s)
                        elif raw:
                            strings.append(raw.decode('latin1'))
                    break
        if x.mnemonic == 'bl':
            try:
                calls.append(int(x.op_str.split('#')[1], 0))
            except Exception:
                pass
    return strings, calls

for (model, state, writer) in (
        ('X-H2', 'new', 0x2fafcb8), ('X-H2', 'old', 0x2fb3b40),
        ('X-H2S', 'new', 0x32c92b4), ('X-T5', 'new', 0x2eefa78)):
    b = load(model, state, 1)
    starts = starts_index(b)
    fs, fe = func_range(b, starts, writer)
    ss, cs = scan(b, fs, fe)
    print(f'\n===== {model} {state}: функция {fs:#x}..{fe:#x} (писатель 0xa8)')
    print('  строки:', ss[:12])
    print('  вызывает:', [hex(c) for c in sorted(set(cs))][:20])
    for c in sorted(set(cs))[:12]:
        try:
            cfs, cfe = func_range(b, starts, c)
            if not (b.base <= cfs < b.end):
                continue
        except Exception:
            continue
        ss2, cs2 = scan(b, cfs, cfe)
        if ss2:
            print(f'    {c:#x} (функция {cfs:#x}): {ss2[:6]}')
