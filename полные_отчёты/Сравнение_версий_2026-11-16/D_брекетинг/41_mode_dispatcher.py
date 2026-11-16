# -*- coding: utf-8 -*-
"""D4: поиск функции-диспетчера по полю 0x3978.

Из строгих сравнений поля (39_mode_domain2) группируем по функции; функции, где
поле сравнивается с 3+ разными значениями, — кандидаты в switch/enum-диспетчер.
Печатаем такие функции и их строки (имена режимов/логов).
"""
import sys, re
from collections import defaultdict, deque
sys.path.insert(0, r'<корень проекта>\Анализ_прошивки\Сравнение_версий_2026-11-16\D_брекетинг')
from dhelp import *  # noqa

MODEL, STATE = 'X-H2', 'new'
b = load(MODEL, STATE, 1)
d = b.data

starts = []
for o in range(0, len(d) - 3, 4):
    w = struct.unpack_from('<I', d, o)[0]
    if (w & 0xffc07fff) in (0xa9807bfd, 0xa9007bfd):
        starts.append(b.base + o)
starts.sort()

def func_of(a):
    lo, hi = 0, len(starts) - 1
    while lo < hi:
        mid = (lo + hi + 1) // 2
        if starts[mid] <= a:
            lo = mid
        else:
            hi = mid - 1
    return starts[lo]

def func_end(f):
    i = starts.index(f)
    return starts[i + 1] if i + 1 < len(starts) else b.end

def decode(raw):
    for enc in ('shift_jis', 'cp932'):
        try:
            return raw.decode(enc)
        except Exception:
            pass
    return raw.decode('latin1')

def strings_in(lo, hi, limit=30):
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
                if 0 <= o2 < len(d):
                    raw = d[o2:o2 + 80].split(b'\x00')[0]
                    if raw and len(raw) >= 4:
                        s = decode(raw)
                        if all(32 <= ord(c) < 127 or ord(c) > 0x2000 for c in s):
                            out.append(s)
                break
    return out[:limit]

recent = deque(maxlen=5)
per_func = defaultdict(set)
for x in all_insns(b):
    if x.mnemonic == '.byte':
        continue
    ops = x.op_str
    m = re.search(r'\[x\d+, #0x3978\]', ops)
    src = None
    if m and x.mnemonic in ('ldr', 'ldrh', 'ldrsw'):
        dst = ops.split(',')[0].strip()
        src = dst[1:] if dst.startswith(('w', 'x')) else dst
    if x.mnemonic in ('cmp', 'subs'):
        op0 = ops.split(',')[0].strip()
        imm = re.search(r'#(0x[0-9a-f]+|\d+)', ops)
        reg = op0[1:] if op0.startswith(('w', 'x')) else op0
        for a, mn, o, sr in reversed(recent):
            if sr == reg and imm:
                per_func[func_of(x.address)].add(int(imm.group(1), 0))
                break
    recent.append((x.address, x.mnemonic, ops, src))

print(f'функций, где поле сравнивается с imm: {len(per_func)}')
cand = [(f, v) for f, v in per_func.items() if len(v) >= 3]
print(f'из них с 3+ значениями: {len(cand)}')
for f, vals in sorted(cand, key=lambda kv: -len(kv[1])):
    print(f'\n=== {f:#x}: значения {[hex(v) for v in sorted(vals)]}')
    print('   строки:', strings_in(f, func_end(f))[:10])
