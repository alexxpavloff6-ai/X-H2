"""F: корректная трассировка указателя &S в пределах функции с учётом wN/xN.

Ключевые правила:
  * ключ регистра всегда xN (wN — это же регистр);
  * любая запись в регистр (mov/movz/ldr/addc/...) сбрасывает его метку, кроме
    add/mov с известным источником;
  * после bl x0..x18 сбрасываются (упрощение: x0..x7 и x9..x15).
"""
import sys, re, json, struct, collections
sys.path.insert(0, '<корень проекта>/Анализ_прошивки/Сравнение_версий_2026-11-16/F_режим_съёмки')
from fhelp import *
import fwcommon

S, SZ = 0x244eb20, 0x2940
PAGE = 0x244e000


def reg_of(tok):
    tok = tok.strip()
    m = re.fullmatch(r'[xw](\d+)', tok)
    return f'x{m.group(1)}' if m else None


def base_sites(b):
    out = []
    for va, reg in adrp_sites(b, PAGE):
        r = reg_of(f'x{reg}')
        for x in insns(b, va + 4, 3):
            m = re.fullmatch(r'(x\d+), (x\d+), #(-?0x[0-9a-f]+|-?\d+)', x.op_str)
            if x.mnemonic == 'add' and m and reg_of(m.group(2)) == r:
                if int(m.group(3), 0) == 0xb20:
                    out.append((x.address, reg_of(m.group(1))))
                break
            if x.mnemonic in ('bl', 'ret', 'br', 'b'):
                break
    return out


def trace(b, site, dst, count=80):
    """Вернуть (calls, stores): calls=[(site,tgt,{argreg:off})], stores=[(site,insn,off)]"""
    known = {dst: 0}          # регистр -> смещение от S
    spill = {}                # [sp,#off] -> смещение от S
    calls, stores = [], []
    for x in insns(b, site + 4, count):
        s = x.op_str
        ops = [p.strip() for p in s.split(',')]
        w = x.mnemonic
        dstreg = reg_of(ops[0]) if ops else None
        mem = re.search(r'\[(x\d+)(?:,\s*#(-?0x[0-9a-f]+|-?\d+))?\]', s)
        # spill/load через стек
        if mem and mem.group(1) == 'x29' or (mem and mem.group(1) == 'sp'):
            off = int(mem.group(2), 0) if mem.group(2) else 0
            src = reg_of(ops[0]) if w == 'str' else None
            if w == 'str' and src in known:
                spill[off] = known[src]
            if w == 'ldr' and dstreg and off in spill:
                known[dstreg] = spill[off]
                continue
        # add reg,reg,#imm
        m = re.fullmatch(r'(x\d+), (x\d+), #(-?0x[0-9a-f]+|-?\d+)', s)
        if w == 'add' and m:
            a, bb, im = reg_of(m.group(1)), reg_of(m.group(2)), int(m.group(3), 0)
            if bb in known:
                known[a] = known[bb] + im
                continue
            known.pop(a, None)
            continue
        if w in ('mov', 'orr') and len(ops) == 2:
            a, bb = reg_of(ops[0]), reg_of(ops[1])
            if bb in known:
                known[a] = known[bb]
            else:
                known.pop(a, None)
            continue
        # запись в память относительно известного регистра S+off
        if mem and mem.group(1) in known:
            off = int(mem.group(2), 0) if mem.group(2) else 0
            tgt = known[mem.group(1)] + off
            if w.startswith('st'):
                if 0 <= tgt < SZ:
                    stores.append((x.address, f'{w} {s}', tgt))
            continue
        if w == 'bl':
            tgt = int(s.split('#')[1], 0)
            args = {r: v for r, v in known.items() if re.fullmatch(r'x[0-7]', r)}
            if args:
                calls.append((x.address, tgt, args))
            for i in range(8):
                known.pop(f'x{i}', None)
            continue
        if w in ('ret', 'br', 'b'):
            break
        if dstreg:
            known.pop(dstreg, None)
    return calls, stores


for idx in (0, 1):
    b = load('X-H2', 'new', idx)
    sites = base_sites(b)
    callees = collections.Counter()
    callee_args = collections.defaultdict(set)
    direct = []
    for site, dst in sites:
        calls, stores = trace(b, site, dst)
        direct += stores
        for csite, tgt, args in calls:
            callees[tgt] += 1
            for r, v in args.items():
                callee_args[tgt].add((r, v))
    print(f'== b{idx}: сайтов {len(sites)}, прямых записей {len(direct)}, callee {len(callees)}')
    for a, insn, off in direct:
        print(f'   {a:x}: {insn} -> S+{off:#x}')
    for tgt, n in callees.most_common(20):
        print(f'  callee {tgt:#x} n={n} args={sorted(callee_args[tgt])}')
