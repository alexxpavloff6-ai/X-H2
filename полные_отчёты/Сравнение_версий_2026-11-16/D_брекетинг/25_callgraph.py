# -*- coding: utf-8 -*-
"""D2: граф вызовов вверх от функции подготовки кадра (0x2ce8f3c) и от
многокадровой RECIF/offset функции (0x2dd1478, 0x2dd0fc4), плюс строки,
на которые ссылается каждая функция (ищем признаки режимов съёмки).

Индекс начал функций строится по маске пролога `stp x29,x30,[sp,#-N]!`.
"""
import sys, re, struct, json
sys.path.insert(0, r'<корень проекта>\Анализ_прошивки\Сравнение_версий_2026-11-16\D_брекетинг')
from dhelp import *  # noqa

model, state = 'X-H2', 'new'
b = load(model, state, 1)
d = b.data

# --- индекс начал функций ---
starts = []
for o in range(0, len(d) - 3, 4):
    w = struct.unpack_from('<I', d, o)[0]
    if (w & 0xffc07fff) == 0xa9807bfd:
        starts.append(b.base + o)
starts.sort()
print('функций по прологу:', len(starts))

def func_of(addr):
    lo, hi = 0, len(starts) - 1
    if addr < starts[0]:
        return None
    while lo < hi:
        mid = (lo + hi + 1) // 2
        if starts[mid] <= addr:
            lo = mid
        else:
            hi = mid - 1
    return starts[lo]

def func_end(start):
    i = starts.index(start)
    return starts[i + 1] if i + 1 < len(starts) else b.end

# --- карта вызовов: цель -> список вызывающих ---
callers = {}
for o in range(0, len(d) - 3, 4):
    w = struct.unpack_from('<I', d, o)[0]
    if (w & 0x7c000000) != 0x14000000:
        continue
    imm = w & 0x3ffffff
    if imm & (1 << 25):
        imm -= 1 << 26
    tgt = b.base + o + imm * 4
    if not (b.base <= tgt < b.end):
        continue
    callers.setdefault(tgt, []).append((b.base + o, 'bl' if w & 0x80000000 else 'b'))

def decode(raw):
    for enc in ('shift_jis', 'cp932'):
        try:
            return raw.decode(enc)
        except Exception:
            pass
    return raw.decode('latin1')

KW = re.compile(r'BKT|BRACKET|ISO|FSIM|FILM|HDR|MULTI|DRIVE|CLARITY|PIXEL|SHIFT|RAW|'
                r'DEVELOP|RECIF|RSZ|MREC|RECP|OFFSET|BULB|CONTINU|SINGLE|STILL|MOVIE|'
                r'連写|ブラケット|多重|現像|HDR', re.I)

def interesting_strings(fstart, fend):
    out = []
    ins = [x for x in all_insns(b, fstart, fend) if x.mnemonic != '.byte']
    for i, x in enumerate(ins):
        if x.mnemonic != 'adrp':
            continue
        page = int(x.op_str.split('#')[1], 0)
        reg = x.op_str.split(',')[0]
        for y in ins[i + 1:i + 3]:
            if y.mnemonic == 'add' and y.op_str.startswith(reg + ', '):
                try:
                    off = int(y.op_str.split('#')[1], 0)
                except Exception:
                    break
                s = raw_str = None
                o2 = b.off(page + off)
                if 0 <= o2 < len(b.data):
                    raw = b.data[o2:o2 + 120].split(b'\x00')[0]
                    if raw and all(32 <= c < 127 for c in raw):
                        s = raw.decode('latin1')
                if s and KW.search(s):
                    out.append(s)
                break
    return out

def walk(seed, depth=3, seen=None, rows=None):
    if seen is None:
        seen, rows = set(), []
    fs = func_of(seed)
    if fs is None or fs in seen:
        return rows
    seen.add(fs)
    rows.append((fs, depth))
    if depth > 0:
        for site, kind in callers.get(fs, []):
            walk(site, depth - 1, seen, rows)
    return rows

for seed, name in ((0x2ce8f3c, 'подготовка кадра'), (0x2dd1478, 'RECIF/offset многокадровая'),
                   (0x2dd0fc4, 'соседняя 0x2dd0fc4')):
    print(f'\n===== вверх от {name} {seed:#x}')
    rows = walk(seed)
    for fs, depth in rows:
        ss = interesting_strings(fs, func_end(fs))
        cs = [hex(a) for a, _ in callers.get(fs, [])]
        print(f'  {"  " * (3 - depth)}{fs:#x} (callers: {cs[:6]})')
        if ss:
            for s in ss[:6]:
                print(f'        "{s}"')
