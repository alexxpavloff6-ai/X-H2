# -*- coding: utf-8 -*-
"""D: точные границы функции подготовки кадра и поля commit (x22) / params (x19),
которые она пишет. Функция 5.33 начинается 0x2ce8f3c и заканчивается ret 0x2cea030
(дальше 0x2cea034 — уже другая функция). Для old границы определяются как
максимальный достижимый адрес от входа.

Запуск: python 10_commit_fields.py
"""
import sys, re
sys.path.insert(0, r'<корень проекта>\Анализ_прошивки\Сравнение_версий_2026-11-16\D_брекетинг')
from dhelp import *  # noqa
from collections import deque

TERM = ('ret', 'br', 'blr')
MEM = re.compile(r'\[(x\d+)(?:, #0x([0-9a-f]+))?\]')


def reach(model, tag, start, maxbytes=0x6000):
    b = load(model, tag, 1)
    fl = []
    for x in all_insns(b, start, start + maxbytes):
        if x.mnemonic == '.byte':
            continue
        fl.append(x)
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
    instrs = []
    for a in seen:
        instrs.extend(blocks[a])
    instrs.sort(key=lambda x: x.address)
    return b, instrs


for tag, start in (('old', 0x2cecf2c), ('new', 0x2ce8f3c)):
    b, ins = reach('X-H2', tag, start)
    lo, hi = ins[0].address, ins[-1].address
    print(f'=== X-H2 {tag}: достижимо {lo:#x}..{hi:#x} ({len(ins)} instr)')
    st = {}
    for x in ins:
        if x.mnemonic not in ('str', 'strh', 'strb', 'stur', 'sturh', 'sturb'):
            continue
        m = MEM.search(x.op_str)
        if not m:
            continue
        st.setdefault((m.group(1), int(m.group(2), 16) if m.group(2) else 0), []).append(x.address)
    for base in ('x19', 'x22'):
        print(f'  --- {base}')
        for k in sorted([k for k in st if k[0] == base], key=lambda k: k[1]):
            print(f'    +{k[1]:#06x}: {[hex(a) for a in st[k]]}')
