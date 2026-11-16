"""F: найти функции, которым ПЕРЕДАЮТ &S (x0..x7 = 0x244eb20), и проверить,
пишут ли они в поля структуры.

Метод: для каждого ADRP+ADD #0xb20 отслеживаем, куда девается указатель —
в стек ([sp,#off]) или в регистр; при `ldr xN,[sp,#off]` возвращаем S в xN;
при `bl` с S в x0..x7 запоминаем callee. Дальше в callee ищем str/strh/strb
относительно входного x0 (без перезаписи x0).
"""
import sys, re, json, struct, collections
sys.path.insert(0, '<корень проекта>/Анализ_прошивки/Сравнение_версий_2026-11-16/F_режим_съёмки')
from fhelp import *
import fwcommon

S, SZ = 0x244eb20, 0x2940
PAGE = 0x244e000


def base_sites(b):
    out = []
    for va, reg in adrp_sites(b, PAGE):
        r = f'x{reg}'
        for x in insns(b, va + 4, 3):
            m = re.fullmatch(r'(x\d+), (x\d+), #(-?0x[0-9a-f]+|-?\d+)', x.op_str)
            if x.mnemonic == 'add' and m and m.group(2) == r:
                if int(m.group(3), 0) == 0xb20:
                    out.append((x.address, m.group(1)))
                break
            if x.mnemonic in ('bl', 'ret', 'br', 'b'):
                break
    return out


def who_gets_S(b, site, dst):
    """Проследить, куда идёт указатель S из dst после site."""
    ptr = {dst: 'S'}
    spill = {}
    calls = []
    for x in insns(b, site + 4, 80):
        ops = [p.strip() for p in x.op_str.split(',')]
        # spill
        m = re.fullmatch(r'(x\d+), \[sp(?:, #(-?0x[0-9a-f]+|-?\d+))?\]', x.op_str)
        if x.mnemonic == 'str' and m and m.group(1) in ptr:
            spill[int(m.group(2), 0) if m.group(2) else 0] = 'S'
            continue
        if x.mnemonic == 'ldr' and m and int(m.group(2), 0) if (m and m.group(2)) else False:
            off = int(m.group(2), 0) if m.group(2) else 0
            if off in spill:
                ptr[m.group(1)] = 'S'
                continue
        if x.mnemonic == 'add' and len(ops) == 3:
            mm = re.fullmatch(r'(x\d+), (x\d+), #(-?0x[0-9a-f]+|-?\d+)', x.op_str)
            if mm and mm.group(2) in ptr:
                ptr[mm.group(1)] = ptr[mm.group(2)] + '+' + str(int(mm.group(3), 0))
                continue
        if x.mnemonic == 'bl':
            tgt = int(x.op_str.split('#')[1], 0)
            args = [(f'x{i}', ptr.get(f'x{i}')) for i in range(8) if f'x{i}' in ptr]
            if args:
                calls.append((x.address, tgt, args))
            # после bl x0..x7 могут быть испорчены
            for i in range(8):
                ptr.pop(f'x{i}', None)
            continue
        if x.mnemonic in ('ret', 'br', 'ret'):
            break
        if x.mnemonic == 'b':
            break
        if ops and re.fullmatch(r'[xw]\d+', ops[0]):
            ptr.pop(ops[0], None)
    return calls


def writes_in_callee(b, fs, fe):
    """str/strh/strb относительно x0 (входной указатель S), пока x0 не перезаписан."""
    rows = []
    x0 = 'S'
    for x in insns(b, fs, max(1, (fe - fs) // 4)):
        ops = [p.strip() for p in x.op_str.split(',')]
        mem = re.search(r'\[(x\d+)(?:,\s*#(-?0x[0-9a-f]+|-?\d+))?\]', x.op_str)
        if mem and mem.group(1) == 'x0' and x0 == 'S' and x.mnemonic.startswith('st'):
            off = int(mem.group(2), 0) if mem.group(2) else 0
            if 0 <= off < SZ:
                rows.append((x.address, f'{x.mnemonic} {x.op_str}', off))
    return rows


for idx in (0, 1):
    b = load('X-H2', 'new', idx)
    sites = base_sites(b)
    allcalls = collections.Counter()
    callee_args = {}
    for site, dst in sites:
        for csite, tgt, args in who_gets_S(b, site, dst):
            allcalls[tgt] += 1
            callee_args.setdefault(tgt, set()).update(a for a, v in args if v == 'S')
    print(f'== b{idx}: сайтов {len(sites)}, callee c &S: {len(allcalls)}')
    for tgt, n in allcalls.most_common(30):
        fs, fe = func_range(b, tgt)
        w = writes_in_callee(b, fs, fe)
        print(f'  callee {tgt:#x} n={n} args={sorted(callee_args[tgt])} writes={len(w)}')
        for a, ins, off in w[:8]:
            print(f'      {a:x}: {ins} -> S+{off:#x}')
