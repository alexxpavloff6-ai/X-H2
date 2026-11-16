# -*- coding: utf-8 -*-
"""D2: есть ли в графе вызывающих наших функций режимные строки (BKT/ブラケット/
連写/多重/HDR/現像/RAW/CLARITY/インターバル...)?

Один проход по блоку 1: собираем
 - индекс начал функций (маска пролога stp x29,x30,[sp,#-N]!);
 - карту вызовов (цель -> вызывающие);
 - ссылки на строки (adrp+add -> строка) с адресом кода;
Затем:
 - находим функции, ссылающиеся на «режимные» строки;
 - строим множество функций-предков для целевых (prep 0x2ce8f3c, RECIF 0x2dd1478,
   0x2dd0fc4, 0x2dd1bb0) вверх до глубины 4;
 - печатаем пересечение и всех предков с их строками.
"""
import sys, re, struct, json
sys.path.insert(0, r'<корень проекта>\Анализ_прошивки\Сравнение_версий_2026-11-16\D_брекетинг')
from dhelp import *  # noqa
from collections import deque

model, state = 'X-H2', 'new'
b = load(model, state, 1)
d = b.data

starts = []
for o in range(0, len(d) - 3, 4):
    if (struct.unpack_from('<I', d, o)[0] & 0xffc07fff) == 0xa9807bfd:
        starts.append(b.base + o)
starts.sort()
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

# --- карта вызовов + строки одним проходом ---
callers = {}
string_refs = []          # (code_addr, string)
last_adrp = {}
for x in all_insns(b):
    if x.mnemonic == '.byte':
        continue
    if x.mnemonic == 'adrp':
        try:
            last_adrp[x.op_str.split(',')[0]] = int(x.op_str.split('#')[1], 0)
        except Exception:
            pass
        continue
    if x.mnemonic == 'add' and re.match(r'x\d+, x\d+, #', x.op_str):
        parts = [p.strip() for p in x.op_str.split(',')]
        base, off = parts[1], int(parts[2].split('#')[1], 0)
        if base in last_adrp:
            va = last_adrp[base] + off
            o2 = b.off(va)
            if 0 <= o2 < len(b.data):
                raw = d[o2:o2 + 96].split(b'\x00')[0]
                if raw and len(raw) >= 4 and all(32 <= c < 127 for c in raw):
                    string_refs.append((x.address, raw.decode('latin1')))
        continue
    if x.mnemonic == 'bl':
        try:
            tgt = int(x.op_str.split('#')[1], 0)
        except Exception:
            continue
        if b.base <= tgt < b.end:
            callers.setdefault(tgt, []).append(x.address)

KW = re.compile(r'BKT|BRACKET|ブラケット|連写|多重|HDR|現像|RAW|CLARITY|インターバル|'
                r'MULTI|PIXEL|SHIFT|シフト|深度|合成|FSIM|フィルム|FILM', re.I)
mode_funcs = {}
for a, s in string_refs:
    if KW.search(s):
        fs = func_of(a)
        if fs is not None:
            mode_funcs.setdefault(fs, set()).add(s)
print('функций с режимными строками:', len(mode_funcs))

def ancestors(seed, depth=4):
    seen = {}
    q = deque([(seed, 0)])
    while q:
        a, dep = q.popleft()
        fs = func_of(a)
        if fs is None or fs in seen:
            continue
        seen[fs] = dep
        if dep < depth:
            for site in callers.get(fs, []):
                q.append((site, dep + 1))
    return seen

targets = {0x2ce8f3c: 'подготовка кадра', 0x2dd1478: 'RECIF/offset',
           0x2dd0fc4: '0x2dd0fc4', 0x2dd1bb0: 'вызывающий prep'}
allanc = {}
for t, name in targets.items():
    anc = ancestors(t)
    allanc.update({k: min(v, allanc.get(k, 99)) for k, v in anc.items()})
    inter = sorted(set(anc) & set(mode_funcs))
    print(f'\n=== {name} {t:#x}: предков {len(anc)}, из них с режимными строками: {len(inter)}')
    for fs in inter:
        print(f'   {fs:#x} ({anc[fs]}): {sorted(mode_funcs[fs])[:6]}')

print('\n=== все предки с любыми строками (до 4 уровней) ===')
rows = []
for fs, dep in sorted(allanc.items(), key=lambda kv: kv[1]):
    ss = sorted({s for a, s in string_refs if func_of(a) == fs})
    rows.append((dep, fs, ss))
for dep, fs, ss in rows:
    if ss:
        print(f'  [{dep}] {fs:#x}: {ss[:6]}')
json.dump({'mode_funcs': {hex(k): sorted(v) for k, v in mode_funcs.items()},
           'ancestors': {hex(k): v for k, v in allanc.items()}},
          open('callgraph_modes.json', 'w', encoding='utf8'), ensure_ascii=False, indent=1)
