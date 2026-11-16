"""F: карта сравнений полей S+0 (mode) и S+0xb4 (sub) по функциям X-H2 5.33 b1.

Для каждого чтения [0x244eb20] / [0x244ebd4] смотрим cmp/sub в пределах 8
инструкций и собираем множества значений. Функции с большим набором значений —
вероятные «диспетчеры режима».
"""
import sys, re, json, struct, collections
sys.path.insert(0, '<корень проекта>/Анализ_прошивки/Сравнение_версий_2026-11-16/F_режим_съёмки')
from fhelp import *

FIELDS = {0x244eb20: 'mode', 0x244ebd4: 'sub'}


def sites_of(b, target, win=40):
    """Найти чтения [target] через adrp+add/ldr и вернуть (site, reg)."""
    out = []
    page = target & ~0xfff
    for va, reg in adrp_sites(b, page):
        r = f'x{reg}'
        cur = {r: page}
        for x in insns(b, va + 4, win):
            ops = [p.strip() for p in x.op_str.split(',')]
            mem = re.search(r'\[(x\d+)(?:,\s*#(-?0x[0-9a-f]+|-?\d+))?\]', x.op_str)
            if mem and mem.group(1) in cur:
                off = int(mem.group(2), 0) if mem.group(2) else 0
                if cur[mem.group(1)] + off == target:
                    out.append((x.address, x.mnemonic, ops[0] if ops else ''))
            if x.mnemonic == 'add' and len(ops) == 3:
                m = re.fullmatch(r'(x\d+), (x\d+), #(-?0x[0-9a-f]+|-?\d+)', x.op_str)
                if m and m.group(2) in cur:
                    cur[m.group(1)] = cur[m.group(2)] + int(m.group(3), 0)
                    continue
            if x.mnemonic in ('bl', 'b', 'ret', 'br', 'blr'):
                break
            if ops and re.fullmatch(r'[xw]\d+', ops[0]) and ops[0] in cur and ops[0] != r:
                del cur[ops[0]]
    return out


for fld, name in FIELDS.items():
    for idx in (1,):
        b = load('X-H2', 'new', idx)
        reads = sites_of(b, fld)
        # значение регистра-приёмника -> сравнения
        per_func = collections.defaultdict(lambda: collections.Counter())
        detail = collections.defaultdict(list)
        for site, mn, dst in reads:
            if not mn.startswith('ldr') or not dst:
                continue
            vals = set()
            for x in insns(b, site + 4, 8):
                m = re.fullmatch(r'w\d+, #(-?0x[0-9a-f]+|-?\d+)', x.op_str)
                if x.mnemonic in ('cmp', 'sub') and m and x.op_str.split(',')[0].strip() == dst:
                    vals.add(int(m.group(1), 0))
                if x.mnemonic in ('cbz', 'cbnz'):
                    pass
            if vals:
                fs, fe = func_range(b, site)
                per_func[fs].update(vals)
                detail[fs].append((site, sorted(vals)))
        print(f'== {name}: функций с cmp {len(per_func)}')
        for fs, c in sorted(per_func.items(), key=lambda kv: -len(kv[1])):
            print(f'  {fs:#x}: {sorted(c)}')
