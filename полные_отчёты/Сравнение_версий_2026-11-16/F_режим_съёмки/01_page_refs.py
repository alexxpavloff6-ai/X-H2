"""F: все обращения к странице ADRP 0x244e000 (глобалы 0x244eb20 / 0x244ebd4).

Скан по всем блокам/моделям/версиям: ADRP на страницу 0x244e000, затем в окне
до 8 инструкций разворачиваем ADD и смотрим, какой абсолютный адрес читается/
пишется (ldr/str/ldp/stp/ldrb/strb/ldrh/strh, а также add xN,xN,#imm — передача
базы структуры в callee).

Печатает: адрес инструкции, саму инструкцию, целевой абсолютный адрес, тип.
"""
import sys, re, json, struct
sys.path.insert(0, r'<корень проекта>\Анализ_прошивки\Сравнение_версий_2026-11-16')
from fwcommon import *

TARGETS = {0x244eb20: 'G_244eb20', 0x244ebd4: 'G_244ebd4'}
PAGE = 0x244e000

out = []
for model in MODELS:
    for state in ('old', 'new'):
        for idx in (0, 1, 2):
            b = load(model, state, idx)
            sites = adrp_sites(b, PAGE)
            if not sites:
                continue
            print(f'== {model} {b.version} b{idx} base={b.base:#x}: adrp-site={len(sites)}')
            for va, reg in sites:
                r = f'x{reg}'
                cur = PAGE & ~0xfff
                for x in insns(b, va + 4, 10):
                    ops = [p.strip() for p in x.op_str.split(',')]
                    m = re.search(r'#(-?0x[0-9a-f]+|-?\d+)', x.op_str)
                    imm = int(m.group(1), 0) if m else 0
                    if x.mnemonic == 'add' and len(ops) >= 3 and ops[1] == r:
                        tgt = cur + imm
                        if tgt in TARGETS:
                            print(f'  {x.address:x}: {x.mnemonic} {x.op_str}   -> base {tgt:#x} ({TARGETS[tgt]})')
                            out.append(dict(model=model, state=state, idx=idx, site=x.address,
                                            insn=f'{x.mnemonic} {x.op_str}', kind='add-base',
                                            target=tgt))
                        if ops[0] == r:
                            cur = tgt
                            continue
                        # base passed into another reg: `add x0,x1,#imm`
                        if tgt in TARGETS:
                            pass
                        break
                    if x.mnemonic[:3] in ('ldr', 'str', 'ldp', 'stp', 'ldrs', 'ldur', 'stur') and f'[{r}]' in x.op_str.replace('[', '[').replace(']', ']'):
                        tgt = cur + imm
                        if tgt in TARGETS:
                            print(f'  {x.address:x}: {x.mnemonic} {x.op_str}   -> {tgt:#x} ({TARGETS[tgt]})')
                            out.append(dict(model=model, state=state, idx=idx, site=x.address,
                                            insn=f'{x.mnemonic} {x.op_str}', kind=x.mnemonic,
                                            target=tgt))
                    if x.mnemonic in ('bl', 'b', 'ret', 'br', 'blr'):
                        break
                    if ops and ops[0] in (r, 'w' + r[1:]):
                        break

json.dump(out, open(r'<корень проекта>\Анализ_прошивки\Сравнение_версий_2026-11-16\F_режим_съёмки\page_refs.json', 'w'),
          indent=1, ensure_ascii=False)
print('total exact hits', len(out))
