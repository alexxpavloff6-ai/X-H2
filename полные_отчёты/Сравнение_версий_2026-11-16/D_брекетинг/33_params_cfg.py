# -*- coding: utf-8 -*-
"""D3: CFG функции 0x2dd1bb0 (recfCalcRecifParam) — пути к memset(params) и к вызову
подготовки кадра; где задаётся x20 (указатель params).

X-H2 5.33:
  0x2dd1f70: stp...; memset(x20, 0, 0x68); memset(sp+0xd0, 0, 0xcc);
  0x2dd1f94: ldr w0,[x19,#0x3978]; cmp w0,#0x2c ...
  0x2dd2190: add x2,sp,#0xd0; mov x1,x20; mov w0,#0; bl 0x2ce8f3c
Скрипт печатает все записи в x20, пути (с условиями) до memset-блока и до вызова prep.
"""
import sys, re
sys.path.insert(0, r'<корень проекта>\Анализ_прошивки\Сравнение_версий_2026-11-16\D_брекетинг')
from dhelp import *  # noqa
from collections import deque

model, state, start = 'X-H2', 'new', 0x2dd1bb0
b = load(model, state, 1)
fl = [x for x in all_insns(b, start, start + 0x2000) if x.mnemonic != '.byte']
# обрежем по следующему прологу после нескольких ret
end = None
for i, x in enumerate(fl):
    if x.mnemonic == 'ret':
        nxt = fl[i + 1] if i + 1 < len(fl) else None
        if nxt and nxt.mnemonic == 'stp' and 'sp, #-' in nxt.op_str:
            end = i
            break
if end:
    fl = fl[:end + 1]
print(f'функция {start:#x}..{fl[-1].address:#x}, {len(fl)} инструкций')

a2i = {x.address: i for i, x in enumerate(fl)}

def target(x):
    m = re.search(r'#0x([0-9a-f]+)$', x.op_str)
    return int(m.group(1), 16) if m else None

# записи в x20
print('\n--- записи в x20 ---')
for x in fl:
    if re.match(r'x20, ', x.op_str) and x.mnemonic in ('mov', 'add', 'ldr', 'adrp', 'orr', 'and', 'sub'):
        print(f'  {x.address:#x}: {x.mnemonic} {x.op_str}')
    if x.mnemonic == 'add' and re.match(r'x20, x\d+, #', x.op_str):
        print(f'  {x.address:#x}: {x.mnemonic} {x.op_str}')

# CFG
TERM = ('ret', 'br', 'blr')
leaders = {fl[0].address}
for x in fl:
    if x.mnemonic.startswith('b') or x.mnemonic in ('cbz', 'cbnz', 'tbz', 'tbnz', *TERM):
        if x.address + 4 in a2i:
            leaders.add(x.address + 4)
        t = target(x)
        if t in a2i:
            leaders.add(t)
blocks = {}
for a in leaders:
    i = a2i[a]; out = []
    while i < len(fl):
        x = fl[i]; out.append(x); i += 1
        if x.mnemonic.startswith('b') or x.mnemonic in ('cbz', 'cbnz', 'tbz', 'tbnz', *TERM):
            break
    blocks[a] = out

def succs(blk):
    last = blk[-1]; t = target(last)
    if last.mnemonic in TERM:
        return []
    if last.mnemonic == 'b':
        return [t] if t in blocks else []
    out = []
    if last.mnemonic.startswith('b.') or last.mnemonic in ('cbz', 'cbnz', 'tbz', 'tbnz'):
        if t in blocks:
            out.append(t)
    n = last.address + 4
    if n in blocks:
        out.append(n)
    return out

def block_of(addr):
    cand = [a for a in leaders if a <= addr]
    return cand[-1] if cand else None

def path_to(dst):
    dst = block_of(dst)
    st = fl[0].address
    q = deque([st]); prev = {st: None}
    while q:
        a = q.popleft()
        if a == dst:
            p, cur = [], a
            while cur is not None:
                p.append(cur); cur = prev[cur]
            return list(reversed(p))
        for s in succs(blocks[a]):
            if s not in prev:
                prev[s] = a; q.append(s)
    return None

for name, dst in (('memset(params) 0x2dd1f70', 0x2dd1f70),
                  ('вызов prep 0x2dd2190', 0x2dd2190)):
    p = path_to(dst)
    print(f'\n=== путь к {name}: {"найден" if p else "НЕ найден"}')
    if not p:
        continue
    for a in p:
        blk = blocks[a]
        last = blk[-1]
        note = ''
        if last.mnemonic.startswith('b.') or last.mnemonic in ('cbz', 'cbnz', 'tbz', 'tbnz'):
            note = f'   ВЕТВЛЕНИЕ {last.address:#x}: {last.mnemonic} {last.op_str}'
        elif last.mnemonic == 'b':
            note = f'   b -> {last.op_str}'
        print(f'  {a:#010x}..{last.address:#010x} {len(blk):3d} insn{note}')
