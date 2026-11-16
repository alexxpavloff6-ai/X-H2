"""F: функции, работающие со структурой 0x244eb20 — их строки (идентификация полей).

Для каждого adrp+add на 0x244eb20/0x244eb4c в X-H2 5.33 b1/b0 находим функцию,
собираем строковые ссылки внутри неё и печатаем те функции, где есть «смысловые»
строки (mode/bracket/drive/DR/BKT/SIZE/...) или много обращений к структуре.
"""
import sys, re, json, struct, collections
sys.path.insert(0, r'<корень проекта>\Анализ_прошивки\Сравнение_версий_2026-11-16')
from fwcommon import *

PAGE = 0x244e000
KEY = re.compile(r'(mode|Mode|MODE|bkt|Bkt|BKT|bracket|Bracket|DRIVE|Drive|drive|DRange|DR_|film|Film|ISO|iso|shoot|Shoot|rec|Rec|drive)', )

for idx in (0, 1):
    b = load('X-H2', 'new', idx)
    sites = []
    for va, reg in adrp_sites(b, PAGE):
        r = f'x{reg}'
        for x in insns(b, va + 4, 3):
            m = re.fullmatch(r'(x\d+), (x\d+), #(-?0x[0-9a-f]+|-?\d+)', x.op_str)
            if x.mnemonic == 'add' and m and int(m.group(3), 0) in (0xb20, 0xb4c):
                sites.append(x.address)
                break
            if x.mnemonic in ('bl', 'ret', 'br', 'b'):
                break
    funcs = collections.Counter()
    for s in sites:
        fs = func_start(b, s, limit=0x8000)
        funcs[fs] += 1
    print(f'== X-H2 5.33 b{idx}: {len(sites)} sites в {len(funcs)} функциях')
    interesting = []
    for fs, n in sorted(funcs.items(), key=lambda kv: -kv[1]):
        if fs is None:
            continue
        # границы функции: ищем следующий пролог/ret
        end = fs + 0x4000
        strs = string_refs(b, fs, end)
        names = [s for (_a, _h, s) in strs]
        hits = [s for s in names if KEY.search(s)]
        if hits or n >= 6:
            interesting.append((fs, n, hits[:12]))
    for fs, n, hits in interesting[:60]:
        print(f'  func {fs:#x}  sites={n}')
        for h in hits:
            print(f'      "{h}"')
