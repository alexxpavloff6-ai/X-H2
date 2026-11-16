"""F: найти код, логирующий eDotlcdPowoffDrivemode и eBracketMode.

Эти format-строки — прямые «имена» полей. Код, который их использует, читает/
пишет нужное поле и печатает значение → даёт привязку поля к смыслу.
"""
import sys, re, json, struct, collections
sys.path.insert(0, r'<корень проекта>\Анализ_прошивки\Сравнение_версий_2026-11-16')
from fwcommon import *
import fwcommon

TARGETS = [0x1736198, 0x18b6fa9]


def find_refs(b, targets):
    out = collections.defaultdict(list)
    for va, w in iter_words(b):
        if (w & 0x9f000000) != 0x90000000:
            continue
        t = fwcommon._adrp_target(w, va)
        if not t:
            continue
        page, reg = t
        r = f'x{reg}'
        for x in insns(b, va + 4, 3):
            m = re.fullmatch(r'(x\d+), (x\d+), #(-?0x[0-9a-f]+|-?\d+)', x.op_str)
            if x.mnemonic == 'add' and m and m.group(2) == r:
                t2 = page + int(m.group(3), 0)
                if t2 in targets:
                    out[t2].append(x.address)
                break
    return out


for idx in (0, 1):
    b = load('X-H2', 'new', idx)
    refs = find_refs(b, TARGETS)
    for t, sites in refs.items():
        print(f'== b{idx} {t:#x} "{b.cstr(t)}": {len(sites)}')
        for s in sites:
            print(dis(b, s - 40, 22))
            print('---')
