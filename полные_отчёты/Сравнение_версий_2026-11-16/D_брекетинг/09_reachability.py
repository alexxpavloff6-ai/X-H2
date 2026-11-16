# -*- coding: utf-8 -*-
"""D: достижимость участков функции подготовки кадра X-H2 0x2ce8f3c (new).
Показывает, какие участки кода функции реально достижимы от входа, а какие
являются отдельными "продолжениями" (в них входят хвостовым b из другого места).
Нужно, чтобы понять, какая ветка пишет commit+0x80 в каком режиме.
"""
import sys, re
sys.path.insert(0, r'<корень проекта>\Анализ_прошивки\Сравнение_версий_2026-11-16\D_брекетинг')
from dhelp import *  # noqa
from collections import deque

TERM = ('ret', 'br', 'blr')

def build(model, tag, start, idx=1):
    b = load(model, tag, idx)
    fl = func(b, start)
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
    return fl, blocks, succs

if __name__ == '__main__':
    fl, blocks, succs = build('X-H2', 'new', 0x2ce8f3c)
    start = fl[0].address
    seen = {start}; q = deque([start])
    while q:
        a = q.popleft()
        for s in succs(blocks[a]):
            if s not in seen:
                seen.add(s); q.append(s)
    print(f'функция {start:#x}..{fl[-1].address:#x}: блоков {len(blocks)}, достижимо {len(seen)}')
    # покрытие адресов достижимыми блоками
    cov = []
    for a in sorted(seen):
        blk = blocks[a]
        cov.append((blk[0].address, blk[-1].address))
    merged = []
    for s, e in cov:
        if merged and s <= merged[-1][1] + 4:
            merged[-1][1] = max(merged[-1][1], e)
        else:
            merged.append([s, e])
    print('\nдостижимые интервалы:')
    for s, e in merged:
        print(f'  {s:#010x} - {e:#010x}  ({(e-s)//4+1} insn)')
    # недостижимые интервалы
    allc = []
    for a in sorted(blocks):
        blk = blocks[a]
        allc.append((blk[0].address, blk[-1].address))
    mergedall = []
    for s, e in allc:
        if mergedall and s <= mergedall[-1][1] + 4:
            mergedall[-1][1] = max(mergedall[-1][1], e)
        else:
            mergedall.append([s, e])
    print('\nнедостижимые интервалы (вход только извне/b-хвостом):')
    for s, e in mergedall:
        if not any(s >= ms and e <= me for ms, me in merged):
            print(f'  {s:#010x} - {e:#010x}  ({(e-s)//4+1} insn)')
