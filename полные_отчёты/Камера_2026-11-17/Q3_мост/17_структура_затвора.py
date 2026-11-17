# -*- coding: utf-8 -*-
"""Q3 шаг 17: (a) функции, пишущие структуру 0x2299498 (источник фактического затвора);
(b) пересечение функций, читающих свойства сценария, с обращениями к job/params/записи 0x4C."""
import json
import sys
from pathlib import Path

HERE = Path(__file__).resolve().parent
sys.path.insert(0, str(HERE))
from q3common import load, dis, insns, adrp_sites, func_start, adrp_refs  # noqa: E402

BASE = 0x2299498
result = {}

# (a) все ADRP+ADD -> 0x2299498 и последующие str в пределах функции
writers = {}
for idx in (0, 1):
    b = load('X-H2', 'old', idx)
    rows = []
    for va, reg in adrp_sites(b, BASE):
        r = f'x{reg}'
        ok = False
        for ins in insns(b, va, 3):
            if ins.mnemonic == 'add' and ins.op_str.startswith(f'{r}, {r}, #'):
                if (BASE & ~0xfff) + int(ins.op_str.split('#')[1], 0) == BASE:
                    ok = True
                break
        if not ok:
            continue
        fs = func_start(b, va)
        stores = []
        for ins in insns(b, va + 4, 800):
            if ins.mnemonic.startswith('str') and f'[{r},' in ins.op_str:
                stores.append(f'{ins.address:x}: {ins.mnemonic} {ins.op_str}')
            if ins.mnemonic == 'ret':
                break
        if stores:
            rows.append({'adrp': hex(va), 'func': hex(fs) if fs else None, 'stores': stores[:40]})
    writers[f'block{idx}'] = rows
result['struct_0x2299498_writers'] = writers

# (b) функции, обращающиеся к job 0x4C3F088 / state 0x4C33AD8 / record id 0x4C
job_refs = {}
for idx in (0, 1):
    b = load('X-H2', 'old', idx)
    job_refs[f'block{idx}'] = {
        'job_0x4C3F088': adrp_refs(b, 0x4C3F088, window=16),
        'state_0x4C33AD8': adrp_refs(b, 0x4C33AD8, window=16),
    }
result['job_state_refs'] = job_refs

out = []
for idx in (0, 1):
    out.append(f'=== block{idx}: писатели структуры 0x2299498 (по ADRP+ADD) ===')
    for r in writers[f'block{idx}']:
        out.append(f"  func={r['func']} adrp={r['adrp']}")
        for s in r['stores']:
            out.append('    ' + s)
    out.append('')
text = '\n'.join(out)
(HERE / 'структура_затвора_писатели.txt').write_text(text + '\n', encoding='utf-8')
(HERE / 'структура_затвора_писатели.json').write_text(json.dumps(result, ensure_ascii=False, indent=2) + '\n', encoding='utf-8')
print(text[:8000])
print('job refs block1:', len(job_refs['block1']['job_0x4C3F088']), 'state refs block1:', len(job_refs['block1']['state_0x4C33AD8']))
