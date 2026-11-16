"""F: поиск записей в S с учётом ОТРИЦАТЕЛЬНЫХ смещений.

Компилятор может адресовать 0x244eb20 как adrp 0x244f000 + (-0x4e0) или
adrp 0x2452000 + (-0x66e0). Поэтому отслеживаем ADRP на ЛЮБУЮ страницу в
окне 0x244c000..0x2453000 и любые ±imm у add и у ldr/str (включая ldur/stur).
"""
import sys, re, json, struct, collections
sys.path.insert(0, '<корень проекта>/Анализ_прошивки/Сравнение_версий_2026-11-16/F_режим_съёмки')
from fhelp import *
import fwcommon

S, SZ = 0x244eb20, 0x2940
PAGES = [p for p in range(0x244c000, 0x2454000, 0x1000)]


def scan(b):
    acc = []
    for va, w in iter_words(b):
        if (w & 0x9f000000) != 0x90000000:
            continue
        t = fwcommon._adrp_target(w, va)
        if not t or t[0] not in PAGES:
            continue
        page, reg = t
        tracked = {f'x{reg}': page}
        for x in insns(b, va + 4, 40):
            s = x.op_str
            ops = [p.strip() for p in s.split(',')]
            m = re.fullmatch(r'(x\d+), (x\d+), #(-?0x[0-9a-f]+|-?\d+)', s)
            if x.mnemonic == 'add' and m and m.group(2) in tracked:
                tracked[m.group(1)] = tracked[m.group(2)] + int(m.group(3), 0)
                continue
            if x.mnemonic in ('mov', 'orr') and len(ops) == 2 and ops[1] in tracked:
                tracked[ops[0]] = tracked[ops[1]]
                continue
            mem = re.search(r'\[(x\d+)(?:,\s*#(-?0x[0-9a-f]+|-?\d+))?\]', s)
            if mem and mem.group(1) in tracked:
                off = int(mem.group(2), 0) if mem.group(2) else 0
                tgt = tracked[mem.group(1)] + off
                if S <= tgt < S + SZ:
                    acc.append(dict(site=x.address, insn=f'{x.mnemonic} {s}',
                                    field=tgt - S, write=x.mnemonic.startswith('st')))
            # сброс отслеживания при перезаписи регистра
            if ops and re.fullmatch(r'[xw]\d+', ops[0]) and ops[0] in tracked and x.mnemonic not in ('add', 'mov', 'orr'):
                del tracked[ops[0]]
            if x.mnemonic in ('ret', 'br'):
                break
    return acc


tot = collections.Counter()
for idx in (0, 1):
    b = load('X-H2', 'new', idx)
    acc = scan(b)
    w = [a for a in acc if a['write']]
    print(f'== b{idx}: обращений {len(acc)}, записей {len(w)}')
    for a in w:
        print(f"   {a['site']:x}: {a['insn']}  -> S+{a['field']:#x}")
    for a in acc:
        tot[(a['field'], a['write'])] += 1
print('\n-- карта полей (field, write) --')
for (f, wr), n in sorted(tot.items()):
    print(f'  S+{f:#06x} {"W" if wr else "r"} n={n}')
