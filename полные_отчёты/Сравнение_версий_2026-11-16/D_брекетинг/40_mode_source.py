# -*- coding: utf-8 -*-
"""D4: откуда берётся 0x2C.

1) `mov wN,#0x2c` (+movk) с последующей записью в память в пределах 3 инструкций —
   кандидаты в писатели кода режима (в т.ч. в структуру-настройки, откуда он
   копируется в ctx+0x3978 на 0x30871ac из [x19+0x144]).
2) Строки функций, которые ветвятся по 0x2C/0x2D — ищем имена режимов/логов recf*.
"""
import sys, re, struct
sys.path.insert(0, r'<корень проекта>\Анализ_прошивки\Сравнение_версий_2026-11-16\D_брекетинг')
from dhelp import *  # noqa

MODEL, STATE = 'X-H2', 'new'
b = load(MODEL, STATE, 1)
d = b.data

MOV_2C = {0x52800000 | (0x2c << 5) | r for r in range(0, 32)}   # mov wN,#0x2c
print('--- mov wN,#0x2c + запись в память (окно 4) ---')
hits = []
for o in range(0, len(d) - 16, 4):
    if struct.unpack_from('<I', d, o)[0] not in MOV_2C:
        continue
    xs = insns(b, b.base + o, 5)
    if len(xs) < 2:
        continue
    dst = xs[0].op_str.split(',')[0].strip()          # wN
    for y in xs[1:]:
        if y.mnemonic.startswith('str') and y.op_str.startswith(dst + ', '):
            hits.append((b.base + o, f'{xs[0].mnemonic} {xs[0].op_str} | {y.mnemonic} {y.op_str}'))
            break
print(f'найдено: {len(hits)}')
for a, s in hits[:40]:
    print(f'  {a:#x}: {s}')

# --- строки функций с ветвлением по 0x2C/0x2D ---
starts = []
for o in range(0, len(d) - 3, 4):
    w = struct.unpack_from('<I', d, o)[0]
    if (w & 0xffc07fff) == 0xa9807bfd or (w & 0xffc07fff) == 0xa9007bfd:
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

def decode(raw):
    for enc in ('shift_jis', 'cp932'):
        try:
            return raw.decode(enc)
        except Exception:
            pass
    return raw.decode('latin1')

# места сравнения с 0x2C/0x2D рядом с чтением 0x3978 (из 39_mode_domain2)
SITES = {
    0x2c: [0x2dcca40, 0x2dd0d90, 0x2dd0e78, 0x2dd1a34, 0x2dd1cf0, 0x2dd1f9c],
    0x2d: [0x2dcec90, 0x2dceca4, 0x2dcecb4, 0x2dd0eec, 0x2dd0f14, 0x2dd0f80, 0x2dd0fa4],
}

def strings_in(lo, hi, limit=40):
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

for val, sites in SITES.items():
    funcs = sorted({func_of(a) for a in sites})
    print(f'\n=== ветвления по {val:#x}: функции {[hex(f) for f in funcs]}')
    for f in funcs:
        i = starts.index(f)
        fe = starts[i + 1] if i + 1 < len(starts) else b.end
        ss = strings_in(f, fe)
        print(f'  {f:#x}: {ss}')
