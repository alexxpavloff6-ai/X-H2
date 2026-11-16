"""F: у функций, читающих S (0x244eb20), собрать строки и найти смысловые имена.

Использует fhelp.func_range (назад до пролога, вперёд до следующего пролога) и
fhelp.cstr2 (допускает \\r\\n).
"""
import sys, re, json, struct, collections
sys.path.insert(0, '<корень проекта>/Анализ_прошивки/Сравнение_версий_2026-11-16/F_режим_съёмки')
from fhelp import *

S, SZ, PAGE = 0x244eb20, 0x2940, 0x244e000
KEY = re.compile(r'(mode|Mode|MODE|driv|Driv|DRIV|bkt|Bkt|BKT|bracket|Bracket|BRACKET|DR\b|rec|Rec|REC|shoot|Shoot|film|Film|iso|ISO|adv|Adv|ADV)')

for idx in (0, 1):
    b = load('X-H2', 'new', idx)
    sites = []
    for va, reg in adrp_sites(b, PAGE):
        r = f'x{reg}'
        cur = {r: PAGE}
        for x in insns(b, va + 4, 4):
            m = re.fullmatch(r'(x\d+), (x\d+), #(-?0x[0-9a-f]+|-?\d+)', x.op_str)
            if x.mnemonic == 'add' and m:
                if m.group(2) in cur:
                    cur[m.group(1)] = cur[m.group(2)] + int(m.group(3), 0)
                    continue
            break
        if cur.get(r) == S:
            sites.append(x.address)
    print(f'== b{idx}: {len(sites)} сайтов S')
    funcs = {}
    for s in sites:
        fs, fe = func_range(b, s)
        funcs.setdefault((fs, fe), []).append(s)
    print(f'   функций: {len(funcs)}')
    for (fs, fe), ss in sorted(funcs.items(), key=lambda kv: -len(kv[1])):
        strs = [t for (_a, _t, t) in adrp_add_all(b, fs, min(fe, fs + 0x1800)) if t]
        hits = [t for t in strs if KEY.search(t)]
        if len(hits) >= 2 or (hits and len(ss) >= 2):
            print(f'  func {fs:#x}-{fe:#x} sites={len(ss)}:')
            for h in hits[:10]:
                print(f'      {h[:100]}')
