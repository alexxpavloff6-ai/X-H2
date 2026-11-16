# -*- coding: utf-8 -*-
"""D3: кто читает поле +0x60 структуры-записи (params).

params — первые 0x68 байт записи 0xC8 из массива ctx+0x5ca8 (X-H2 5.33).
Ищем:
 1) чтения [xN,#0x60] внутри функции 0x2dd1ec0 (§ recfCalcRecifParam);
 2) по всему блоку 1 — функции, где есть чтение [xN,#0x60] И обращения к полям
    записи +0x30..+0x4c (характерный набор), т.е. вероятные потребители.
"""
import sys, re
sys.path.insert(0, r'<корень проекта>\Анализ_прошивки\Сравнение_версий_2026-11-16\D_брекетинг')
from dhelp import *  # noqa
from collections import defaultdict

model, state = 'X-H2', 'new'
b = load(model, state, 1)
d = b.data

# индекс начал функций: оба варианта пролога
starts = []
for o in range(0, len(d) - 3, 4):
    w = struct.unpack_from('<I', d, o)[0]
    if (w & 0xffc07fff) == 0xa9807bfd:      # stp x29,x30,[sp,#-N]!
        starts.append(b.base + o)
    elif (w & 0xffc07fff) == 0xa9007bfd:    # stp x29,x30,[sp,#N] (без pre-index)
        nxt = struct.unpack_from('<I', d, o + 4)[0] if o + 8 <= len(d) else 0
        if (nxt & 0xffc003ff) == 0x910003fd:  # add x29, sp, #N
            starts.append(b.base + o)
starts = sorted(set(starts))
print('функций:', len(starts))

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

def func_end(fs):
    i = starts.index(fs)
    return starts[i + 1] if i + 1 < len(starts) else b.end

# 1) внутри функции recfCalcRecifParam
fs = 0x2dd1ec0
print(f'\n--- чтения +0x60 в функции recfCalcRecifParam {fs:#x}..{func_end(fs):#x}')
for x in all_insns(b, fs, func_end(fs)):
    if x.mnemonic == '.byte':
        continue
    if re.search(r'#0x60\]', x.op_str) or re.search(r'#0x5c\]', x.op_str) or re.search(r'#0x64\]', x.op_str):
        print(f'  {x.address:#x}: {x.mnemonic} {x.op_str}')

# 2) функции с чтением +0x60 и полями 0x30..0x4c
cand = defaultdict(lambda: {'r60': [], 'fields': set(), 'func': None})
for x in all_insns(b):
    if x.mnemonic == '.byte':
        continue
    m = re.search(r'\[(x\d+), #0x([0-9a-f]+)\]', x.op_str)
    if not m:
        continue
    reg, off = m.group(1), int(m.group(2), 16)
    if x.mnemonic not in ('ldr', 'ldrh', 'ldrb', 'ldrsh', 'str', 'strh', 'strb'):
        continue
    if off == 0x60 and x.mnemonic != 'str':
        f = func_of(x.address)
        cand[f]['r60'].append((x.address, reg, f'{x.mnemonic} {x.op_str}'))
    if 0x30 <= off <= 0x4c:
        f = func_of(x.address)
        cand[f]['fields'].add(reg)
for f, info in sorted(cand.items(), key=lambda kv: -len(kv[1]['r60'])):
    if info['r60'] and len(info['fields']) >= 2:
        print(f'\n=== функция {f:#x}: чтений +0x60: {len(info["r60"])}, '
              f'регистры полей: {sorted(info["fields"])}')
        for a, reg, s in info['r60'][:8]:
            print(f'    {a:#x}: {s}')
