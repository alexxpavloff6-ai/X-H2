# -*- coding: utf-8 -*-
"""D: CFG функции подготовки кадра X-H2 и пути до ключевых мест:
 A) 0x2ce98c0 (вставка патча: commit+0x80 = param<<9)
 B) 0x2cebfc0 (старый расчёт commit+0x80 = w21 - v*32)
Цель ищется как блок, содержащий адрес (а не только лидер).
"""
import sys, re
sys.path.insert(0, r'<корень проекта>\Анализ_прошивки\Сравнение_версий_2026-11-16\D_брекетинг')
from dhelp import *  # noqa
from collections import deque

TERM = ('ret', 'br', 'blr')

def build(model, tag, start):
    b = load(model, tag, 1)
    fl = func(b, start)
    addr2i = {x.address: i for i, x in enumerate(fl)}

    def target(x):
        m = re.search(r'#0x([0-9a-f]+)$', x.op_str)
        return int(m.group(1), 16) if m else None

    leaders = {fl[0].address}
    for x in fl:
        if x.mnemonic.startswith('b') or x.mnemonic in ('cbz', 'cbnz', 'tbz', 'tbnz', *TERM):
            if x.address + 4 in addr2i:
                leaders.add(x.address + 4)
            t = target(x)
            if t in addr2i:
                leaders.add(t)
    leaders = {a for a in leaders if a in addr2i}
    blocks = {}
    for a in leaders:
        i = addr2i[a]
        out = []
        while i < len(fl):
            x = fl[i]
            out.append(x)
            i += 1
            if x.mnemonic.startswith('b') or x.mnemonic in ('cbz', 'cbnz', 'tbz', 'tbnz', *TERM):
                break
        blocks[a] = out

    def succs(blk):
        last = blk[-1]
        t = target(last)
        if last.mnemonic in TERM:
            return []
        if last.mnemonic == 'b':
            return [t] if t in blocks else []
        out = []
        if last.mnemonic.startswith('b.') or last.mnemonic in ('cbz', 'cbnz', 'tbz', 'tbnz'):
            if t in blocks:
                out.append(t)
        nxt = last.address + 4
        if nxt in blocks:
            out.append(nxt)
        return out
    return fl, blocks, succs

fl, blocks, succs = build('X-H2', 'new', 0x2ce8f3c)
leaders = sorted(blocks)
print(f'функция: {len(fl)} инструкций, {len(blocks)} блоков')

def block_of(addr):
    cand = [a for a in leaders if a <= addr]
    return cand[-1] if cand else None

def bfs(dst):
    dst = block_of(dst)
    start = fl[0].address
    q = deque([start]); prev = {start: None}
    while q:
        a = q.popleft()
        if a == dst:
            path, cur = [], a
            while cur is not None:
                path.append(cur); cur = prev[cur]
            return list(reversed(path))
        for s in succs(blocks[a]):
            if s not in prev:
                prev[s] = a; q.append(s)
    return None

def show(dst, name):
    p = bfs(dst)
    print(f'\n=== путь к {name} (блок {block_of(dst):#x}): {"найден" if p else "НЕ найден"}')
    if not p:
        return
    for a in p:
        blk = blocks[a]
        last = blk[-1]
        note = ''
        if last.mnemonic.startswith('b.') or last.mnemonic in ('cbz', 'cbnz', 'tbz', 'tbnz'):
            note = f'  ВЕТВЛЕНИЕ {last.address:#x}: {last.mnemonic} {last.op_str}'
        elif last.mnemonic == 'b':
            note = f'  b -> {last.op_str}'
        print(f'  {a:#010x}..{last.address:#010x}  {len(blk):3d} insn{note}')

show(0x2ce98c0, 'патч 0x2ce98c0')
show(0x2cebfc0, 'старая формула 0x2cebfc0')
