"""F2: ссылки на глобальный указатель [0x4daa6e8] и менеджер 0x4daa6c0.

Ищем ADRP на страницу 0x4daa000 + LDR/STR/ADD с иммедиатом 0x6e8 (и 0x6c0),
а также adrp+add на 0x4daa6c0/0x4daa6e8 напрямую.
"""
import sys, re, struct, collections
sys.path.insert(0, '<корень проекта>/Анализ_прошивки/Сравнение_версий_2026-11-16/F_режим_съёмки')
from fhelp import *
import fwcommon

PAGE = 0x4daa000
TGT = {0x4daa6e8: 'job_ptr', 0x4daa6c0: 'mgr'}

for model in MODELS:
    for state in ('old', 'new'):
        for idx in (0, 1, 2):
            b = load(model, state, idx)
            sites = adrp_sites(b, PAGE)
            if not sites:
                continue
            print(f'== {model} {b.version} b{idx}: adrp на 0x4daa000: {len(sites)}')
            for va, reg in sites:
                r = f'x{reg}'
                cur = {r: PAGE}
                for x in insns(b, va + 4, 12):
                    ops = [p.strip() for p in x.op_str.split(',')]
                    m = re.fullmatch(r'(x\d+), (x\d+), #(-?0x[0-9a-f]+|-?\d+)', x.op_str)
                    if x.mnemonic == 'add' and m and m.group(2) in cur:
                        cur[m.group(1)] = cur[m.group(2)] + int(m.group(3), 0)
                        if cur[m.group(1)] in TGT:
                            print(f'   {x.address:x}: add -> {TGT[cur[m.group(1)]]}')
                        continue
                    mem = re.search(r'\[(x\d+)(?:,\s*#(-?0x[0-9a-f]+|-?\d+))?\]', x.op_str)
                    if mem and mem.group(1) in cur:
                        off = int(mem.group(2), 0) if mem.group(2) else 0
                        t = cur[mem.group(1)] + off
                        if t in TGT:
                            print(f'   {x.address:x}: {x.mnemonic} {x.op_str} -> {TGT[t]}')
                    if x.mnemonic in ('bl', 'b', 'ret', 'br'):
                        break
