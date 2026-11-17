# -*- coding: utf-8 -*-
"""Q3 2-й круг, шаг 27: set-data API 0x14CF124; все его вызовы с id=0x4C
(команда u16 и источник); вызывающие 0x311B930/990/9F0. Цель — кто пишет payload+0x64."""
import json
import re
import sys
from pathlib import Path

HERE = Path(__file__).resolve().parent
sys.path.insert(0, str(HERE))
from q3common import load, dis, bl_callers, insns, func_start  # noqa: E402

b0 = load('X-H2', 'old', 0)
b1 = load('X-H2', 'old', 1)
out = []
out.append('===== block0 set-data API 0x14CF124 =====')
out.append(dis(b0, 0x14CF124, 60))
out.append('')

# все вызовы 0x14CF124 с id=0x4C
rows = []
for idx, b in ((0, b0), (1, b1)):
    for s, k in bl_callers(b, 0x14CF124):
        ctx = insns(b, s - 0x30, 13)
        idval = None
        cmd = None
        for ins in ctx:
            txt = ins.mnemonic + ' ' + ins.op_str
            m = re.fullmatch(r'mov(z)? w0, #(0x[0-9a-f]+|\d+)', txt)
            if m:
                idval = int(m.group(2), 0)
            mc = re.fullmatch(r'mov(z)? w0, #(0x[0-9a-f]+|\d+)', txt)
        # cmd обычно strh w0,[sp,#0x20] после mov w0,#0x16xx; ищем mov w0,#0x16xx
        for ins in ctx:
            txt = ins.mnemonic + ' ' + ins.op_str
            m = re.fullmatch(r'mov(z)? w0, #(0x16[0-9a-f]{2})', txt)
            if m:
                cmd = int(m.group(2), 0)
        if idval == 0x4C:
            rows.append({'block': idx, 'site': hex(s), 'func': hex(func_start(b, s) or 0),
                         'cmd': hex(cmd) if cmd else None,
                         'context': '\n'.join(f'{i.address:x}: {i.mnemonic} {i.op_str}' for i in ctx)})
out.append(f'=== вызовы 0x14CF124 с id=0x4C: {len(rows)} ===')
for r in rows:
    out.append(f"--- block{r['block']} {r['site']} func={r['func']} cmd={r['cmd']} ---")
    out.append(r['context'])
    out.append('')

# вызывающие обёрток 0x311B930/990/9F0
for name, tgt in (('0x311B930', 0x311B930), ('0x311B990', 0x311B990), ('0x311B9F0', 0x311B9F0)):
    cs = []
    for idx, b in ((0, b0), (1, b1)):
        for s, k in bl_callers(b, tgt):
            cs.append({'block': idx, 'site': hex(s), 'func': hex(func_start(b, s) or 0)})
    out.append(f'=== вызовы {name}: {len(cs)} ===')
    for c in cs:
        out.append(str(c))
    out.append('')

text = '\n'.join(out)
(HERE / '2круг_set_data_0x4C.txt').write_text(text + '\n', encoding='utf-8')
(HERE / '2круг_set_data_0x4C.json').write_text(json.dumps(rows, ensure_ascii=False, indent=2) + '\n', encoding='utf-8')
print(text[:12000])
