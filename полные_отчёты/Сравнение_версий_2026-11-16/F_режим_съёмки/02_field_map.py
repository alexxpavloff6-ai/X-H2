"""F: суммаризация page_refs.json + поиск писателей через базу 0x244eb20 / 0x244ebd4.

Логика:
  * берём все ADRP на 0x244e000;
  * в окне до 24 инструкций отслеживаем cur = адрес, на который указывает регистр;
  * любая ldr/str/ldrb/strb/ldrh/strh/ldp/stp по [reg,#imm] даёт абсолютный адрес cur+imm;
  * всё, что попадает в диапазон [0x244eb00, 0x244ec00), печатаем с типом (read/write),
    размером и точным адресом -> это карта полей структуры.
"""
import sys, re, json, struct, collections
sys.path.insert(0, r'<корень проекта>\Анализ_прошивки\Сравнение_версий_2026-11-16')
from fwcommon import *

PAGE = 0x244e000
LO, HI = 0x244eb00, 0x244ec40


def scan(b):
    rows = []
    for va, reg in adrp_sites(b, PAGE):
        r = f'x{reg}'
        cur = PAGE
        tracked = {r: cur}
        for x in insns(b, va + 4, 24):
            ops = [p.strip() for p in x.op_str.split(',')]
            m = re.search(r'#(-?0x[0-9a-f]+|-?\d+)', x.op_str)
            imm = int(m.group(1), 0) if m else 0
            mm = re.match(r'(ldr|str|ldrb|strb|ldrh|strh|ldp|stp|ldrsb|ldrsh|ldrsw|ldur|stur)b?\s+x?\w+,?\s*\[(x\d+)(?:,\s*#(-?0x[0-9a-f]+|-?\d+))?\]',
                          f'{x.mnemonic} {x.op_str}')
            # base reg of memory operand
            mem = re.search(r'\[(x\d+)(?:,\s*#(-?0x[0-9a-f]+|-?\d+))?', x.op_str)
            if mem and mem.group(1) in tracked:
                off = int(mem.group(2), 0) if mem.group(2) else 0
                tgt = tracked[mem.group(1)] + off
                if LO <= tgt < HI:
                    kind = 'W' if x.mnemonic.startswith('st') else 'R'
                    size = {'b': 1, 'h': 2}.get(x.mnemonic[-1] if x.mnemonic[-1] in 'bh' else '', 4)
                    rows.append(dict(site=x.address, insn=f'{x.mnemonic} {x.op_str}', addr=tgt,
                                     kind=kind, size=size, adrp=va))
            if x.mnemonic == 'add' and len(ops) >= 3:
                src, imm2 = ops[1], None
                m2 = re.fullmatch(r'#(-?0x[0-9a-f]+|-?\d+)', ops[2])
                if m2 and src in tracked:
                    imm2 = int(m2.group(1), 0)
                    tracked[ops[0]] = tracked[src] + imm2
                    continue
            if x.mnemonic in ('bl', 'b', 'ret', 'br', 'blr'):
                break
            if ops and re.fullmatch(r'[xw]\d+', ops[0]):
                dst = ops[0]
                if dst in tracked and dst != r:
                    del tracked[dst]
    return rows


res = {}
for model in MODELS:
    for state in ('old', 'new'):
        b = load(model, state, 1)
        rows = scan(b)
        res[f'{model} {b.version}'] = rows
        w = [x for x in rows if x['kind'] == 'W']
        print(f'== {model} {b.version}: refs_in_range={len(rows)} writes={len(w)} '
              f'reads_0xb20={sum(1 for x in rows if x["addr"]==0x244eb20)} '
              f'reads_0xbd4={sum(1 for x in rows if x["addr"]==0x244ebd4)}')
        for x in w:
            print(f'   W {x["site"]:x}: {x["insn"]}  -> {x["addr"]:#x}')

json.dump({k: v for k, v in res.items()}, open('page_refs_full.json', 'w'), indent=1)
# карта полей для new X-H2
h2 = res['X-H2 5.33']
cnt = collections.Counter((x['addr'], x['kind'], x['size']) for x in h2)
print('\n-- карта полей X-H2 5.33 (offset от 0x244e000, kind, size, count) --')
for (a, k, s), n in sorted(cnt.items()):
    print(f'  {a:#x}  +{(a-0x244e000):#05x}  {k}{s}  n={n}')
