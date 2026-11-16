# -*- coding: utf-8 -*-
"""D: что пишет в commit соседняя функция 0x2cea044 (X-H2 new) и её старая копия.
Если сосед заполняет commit+0x58..+0x80, то картина "в old +0x80 не писалось"
нуждается в уточнении: важно, кто именно пишет +0x80 в каждом режиме.
"""
import sys, re
sys.path.insert(0, r'<корень проекта>\Анализ_прошивки\Сравнение_версий_2026-11-16\D_брекетинг')
from dhelp import *  # noqa
from collections import deque
from importlib import import_module
m10 = import_module('10_commit_fields') if False else None

TERM = ('ret', 'br', 'blr')
MEM = re.compile(r'\[(x\d+)(?:, #0x([0-9a-f]+))?\]')


def reach(model, tag, start, maxbytes=0x4000):
    b = load(model, tag, 1)
    fl = [x for x in all_insns(b, start, start + maxbytes) if x.mnemonic != '.byte']
    a2i = {x.address: i for i, x in enumerate(fl)}

    def tgt(x):
        m = re.search(r'#0x([0-9a-f]+)$', x.op_str)
        return int(m.group(1), 16) if m else None
    leaders = {fl[0].address}
    for x in fl:
        if x.mnemonic.startswith('b') or x.mnemonic in ('cbz', 'cbnz', 'tbz', 'tbnz', *TERM):
            if x.address + 4 in a2i:
                leaders.add(x.address + 4)
            t = tgt(x)
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
        last = blk[-1]; t = tgt(last)
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
    seen = {fl[0].address}; q = deque([fl[0].address])
    while q:
        a = q.popleft()
        for s in succs(blocks[a]):
            if s not in seen:
                seen.add(s); q.append(s)
    ins = []
    for a in seen:
        ins.extend(blocks[a])
    ins.sort(key=lambda x: x.address)
    return b, ins


def report(model, tag, start, label):
    b, ins = reach(model, tag, start)
    print(f'=== {label}: {start:#x}..{ins[-1].address:#x} ({len(ins)} instr)')
    st = {}
    for x in ins:
        if x.mnemonic not in ('str', 'strh', 'strb'):
            continue
        mm = MEM.search(x.op_str)
        if not mm:
            continue
        st.setdefault((mm.group(1), int(mm.group(2), 16) if mm.group(2) else 0), []).append(x.address)
    for base in sorted({k[0] for k in st}):
        offs = sorted(k[1] for k in st if k[0] == base)
        if any(o >= 0x50 for o in offs):
            print(f'  {base}: ' + ', '.join(f'+{o:#x}' for o in offs))
    return ins


report('X-H2', 'new', 0x2cea044, 'X-H2 new сосед 0x2cea044')
# старая копия: ищем по уникальному байтовому образцу пролога? Проще: найти вызовы
# старой версии этой функции через строку-якорь. Пока печатаем, что есть.
