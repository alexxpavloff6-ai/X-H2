"""F: что делают с базой структуры 0x244eb20 (add xN,xN,#0xb20).

Для каждого ADRP+ADD #0xb20 (и #0xb4c) в X-H2 5.33 b1 печатаем 4 следующие
инструкции и группируем по «следующему использованию»: ldr/str/ldp/stp или bl
(передача базы в callee).
"""
import sys, re, json, struct, collections
sys.path.insert(0, r'<корень проекта>\Анализ_прошивки\Сравнение_версий_2026-11-16')
from fwcommon import *

PAGE = 0x244e000
b = load('X-H2', 'new', 1)

rows = []
for va, reg in adrp_sites(b, PAGE):
    r = f'x{reg}'
    xs = insns(b, va + 4, 4)
    for i, x in enumerate(xs):
        m = re.fullmatch(r'(x\d+), (x\d+), #(-?0x[0-9a-f]+|-?\d+)', x.op_str)
        if x.mnemonic == 'add' and m and int(m.group(3), 0) in (0xb20, 0xb4c):
            nxt = insns(b, x.address + 4, 3)
            rows.append((x.address, int(m.group(3), 0), m.group(1),
                         ' | '.join(f'{y.mnemonic} {y.op_str}' for y in nxt)))
            break

print(f'всего adrp+add #0xb20/#0xb4c: {len(rows)}')
kinds = collections.Counter()
for a, imm, dst, tail in rows:
    first = tail.split(' | ')[0]
    k = first.split()[0]
    kinds[(imm, k)] += 1
for (imm, k), n in sorted(kinds.items()):
    print(f'  imm={imm:#x} next={k:6s} n={n}')

print('\n-- уникальные хвосты (dst!=x0) --')
tail_c = collections.Counter((imm, t) for a, imm, d, t in rows if not t.startswith('bl'))
for (imm, t), n in tail_c.most_common(80):
    print(f'  {imm:#x}  {t}   n={n}')

print('\n-- callee для bl-хвостов --')
cal = collections.Counter((imm, t) for a, imm, d, t in rows if t.startswith('bl'))
for (imm, t), n in cal.most_common(40):
    print(f'  {imm:#x}  {t}   n={n}')

json.dump([[hex(a), imm, d, t] for a, imm, d, t in rows], open('base_uses.json', 'w'), indent=1)
