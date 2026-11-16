"""F: все записи в структуру S = [0x244eb20, 0x244eb20+0x2940) в блоках 0/1 X-H2 5.33.

Отслеживаем ADRP 0x244e000 + цепочку ADD в пределах 60 инструкций, а также
ldp/stp/str/strb/strh. Если запись найдена — печатаем адрес инструкции, поле и
контекст (10 инструкций до).
"""
import sys, re, json, struct, collections
sys.path.insert(0, r'<корень проекта>\Анализ_прошивки\Сравнение_версий_2026-11-16')
from fwcommon import *

S = 0x244eb20
SZ = 0x2940
PAGE = 0x244e000


def scan(b):
    writes, reads = [], []
    for va, reg in adrp_sites(b, PAGE):
        r = f'x{reg}'
        tracked = {r: PAGE}
        for x in insns(b, va + 4, 60):
            ops = [p.strip() for p in x.op_str.split(',')]
            mem = re.search(r'\[(x\d+)(?:,\s*#(-?0x[0-9a-f]+|-?\d+))?', x.op_str)
            if mem and mem.group(1) in tracked:
                off = int(mem.group(2), 0) if mem.group(2) else 0
                tgt = tracked[mem.group(1)] + off
                if S <= tgt < S + SZ:
                    rec = dict(site=x.address, insn=f'{x.mnemonic} {x.op_str}',
                               addr=tgt, field=tgt - S, adrp=va)
                    (writes if x.mnemonic.startswith('st') else reads).append(rec)
            if x.mnemonic == 'add' and len(ops) >= 3:
                m2 = re.fullmatch(r'#(-?0x[0-9a-f]+|-?\d+)', ops[2])
                if m2 and ops[1] in tracked:
                    tracked[ops[0]] = tracked[ops[1]] + int(m2.group(1), 0)
                    continue
            if x.mnemonic in ('bl', 'b', 'ret', 'br', 'blr'):
                break
            if ops and re.fullmatch(r'[xw]\d+', ops[0]) and ops[0] in tracked and ops[0] != r:
                del tracked[ops[0]]
    return writes, reads


for idx in (0, 1):
    b = load('X-H2', 'new', idx)
    w, r = scan(b)
    print(f'== X-H2 5.33 b{idx}: записей {len(w)}, чтений {len(r)}')
    fld = collections.Counter(x['field'] for x in w)
    for f, n in sorted(fld.items()):
        print(f'   поле +{f:#05x}: {n} записей')
    for x in w[:60]:
        print(f"   {x['site']:x}: {x['insn']}  -> S+{x['field']:#x}")
