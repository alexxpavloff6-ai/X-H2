"""F2: трассировка job-указателя из [0x4daa6e8] и записи полей.

Для каждого места `ldr xN,[base+0x6e8]` (base = adrp 0x4daa000 + mgr) отслеживаем xN
в пределах функции и печатаем все `str/strh/strb ...,[xN,#off]` и передачи в callee.
"""
import sys, re, struct, collections
sys.path.insert(0, '<корень проекта>/Анализ_прошивки/Сравнение_версий_2026-11-16/F_режим_съёмки')
from fhelp import *
import fwcommon

b = load('X-H2', 'new', 1)
MGR = 0x4daa6c0


def reg(t):
    m = re.fullmatch(r'[xw](\d+)', t.strip())
    return f'x{m.group(1)}' if m else None


hits = []
for va, r0 in adrp_sites(b, 0x4daa000):
    r = f'x{r0}'
    cur = {r: 0x4daa000}
    for x in insns(b, va + 4, 20):
        ops = [p.strip() for p in x.op_str.split(',')]
        m = re.fullmatch(r'(x\d+), (x\d+), #(-?0x[0-9a-f]+|-?\d+)', x.op_str)
        if x.mnemonic == 'add' and m and m.group(2) in cur:
            cur[m.group(1)] = cur[m.group(2)] + int(m.group(3), 0)
            continue
        mem = re.search(r'\[(x\d+)(?:,\s*#(-?0x[0-9a-f]+|-?\d+))?\]', x.op_str)
        if mem and mem.group(1) in cur:
            off = int(mem.group(2), 0) if mem.group(2) else 0
            if cur[mem.group(1)] + off == 0x4daa6e8 and x.mnemonic == 'ldr':
                dst = reg(ops[0])
                hits.append((x.address, dst))
        if x.mnemonic in ('bl', 'ret', 'b', 'br'):
            break

print(f'загрузок [0x4daa6e8]: {len(hits)}')
for site, dst in hits:
    print(f'== {site:x}: job -> {dst}')
    known = {dst: 0}
    for x in insns(b, site + 4, 60):
        ops = [p.strip() for p in x.op_str.split(',')]
        m = re.fullmatch(r'(x\d+), (x\d+), #(-?0x[0-9a-f]+|-?\d+)', x.op_str)
        if x.mnemonic == 'add' and m and m.group(2) in known:
            known[m.group(1)] = known[m.group(2)] + int(m.group(3), 0)
            continue
        if x.mnemonic in ('mov', 'orr') and len(ops) == 2 and ops[1] in known:
            known[ops[0]] = known[ops[1]]
            continue
        mem = re.search(r'\[(x\d+)(?:,\s*#(-?0x[0-9a-f]+|-?\d+))?\]', x.op_str)
        if mem and mem.group(1) in known:
            off = int(mem.group(2), 0) if mem.group(2) else 0
            f = known[mem.group(1)] + off
            print(f'    {x.address:x}: {x.mnemonic} {x.op_str}   (job+{f:#x})')
        if x.mnemonic == 'bl':
            args = [f'{r}={v:#x}' for r, v in known.items() if r in ('x0', 'x1', 'x2', 'x3')]
            if args:
                print(f'    {x.address:x}: bl {x.op_str}  args {args}')
            for i in range(8):
                known.pop(f'x{i}', None)
            continue
        if x.mnemonic in ('ret', 'b'):
            break
        if ops and reg(ops[0]) and reg(ops[0]) in known:
            known.pop(reg(ops[0]), None)
