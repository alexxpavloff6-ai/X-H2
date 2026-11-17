# -*- coding: utf-8 -*-
"""Q3 4-й круг, шаг 48: писатели inner[0x784] (code выдержки 0..17) — скан STR offset 0x784."""
import struct
import sys
from pathlib import Path

HERE = Path(__file__).resolve().parent
sys.path.insert(0, str(HERE))
from q3common import load, dis, func_start  # noqa: E402
import fwcommon  # noqa: E402

b0 = load('X-H2', 'old', 0)
b1 = load('X-H2', 'old', 1)
out = []
# STR Wt,[Xn,#0x784]: imm12=0x1E1 ; STRH: imm12=0x784/2=0x3C2
for idx, b in ((0, b0), (1, b1)):
    sites = []
    for o in range(0, len(b.data) - 3, 4):
        w = struct.unpack_from('<I', b.data, o)[0]
        op = w & 0xFFC00000
        imm = (w >> 10) & 0xFFF
        if (op == 0xB9000000 and imm == 0x1E1) or (op == 0x79000000 and imm == 0x3C2):
            va = b.base + o
            ins = list(fwcommon.insns(b, va, 1))[0]
            sites.append((va, f'{ins.mnemonic} {ins.op_str}', func_start(b, va)))
            if len(sites) >= 30:
                break
    out.append(f'=== str [x?,#0x784] block{idx}: {len(sites)} ===')
    for va, txt, fs in sites:
        out.append(f'  {va:#x}: {txt}  func={fs:#x}' if fs else f'  {va:#x}: {txt}')
    out.append('')
text = '\n'.join(out)
(HERE / '4круг_писатели_0x784.txt').write_text(text + '\n', encoding='utf-8')
print(text[:5000])
