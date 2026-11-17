# -*- coding: utf-8 -*-
"""Q3 шаг 13: писатели источника фактического затвора 0x229AE34 и выдержки 0x229AE2C;
функции, сочетающие CONTINUOUS+REC_VIEW+SHUTTER_TYPE."""
import json
import sys
from pathlib import Path

HERE = Path(__file__).resolve().parent
sys.path.insert(0, str(HERE))
from q3common import load, dis, adrp_refs, bl_callers, insns, func_start  # noqa: E402

out = []
refs = {}
for name, tgt in (('actual_shutter_src', 0x229AE34), ('speed_output_src', 0x229AE2C)):
    refs[name] = {}
    for idx in (0, 1):
        b = load('X-H2', 'old', idx)
        rows = adrp_refs(b, tgt)
        refs[name][f'block{idx}'] = rows
        out.append(f'=== {name} {tgt:#x} block{idx}: {len(rows)} ссылок ===')
        for r in rows:
            out.append('  ' + r['insn'])
        out.append('')

# кандидаты условия дефекта в блоке 1
b1 = load('X-H2', 'old', 1)
for name, va, n in (('block1 0x2C8EDC8 (CONT+REC_VIEW+SHUTTER_TYPE)', 0x2C8EDC8, 120),
                    ('block1 0x2C54750 (CONT+REC_VIEW+SPEED_M+SHUTTER_TYPE)', 0x2C54750, 120)):
    out.append(f'===== {name} =====')
    out.append(dis(b1, va, n))
    out.append('')

text = '\n'.join(out)
(HERE / 'писатели_затвора.txt').write_text(text + '\n', encoding='utf-8')
(HERE / 'писатели_затвора.json').write_text(json.dumps(refs, ensure_ascii=False, indent=2) + '\n', encoding='utf-8')
print(text[:11000])
