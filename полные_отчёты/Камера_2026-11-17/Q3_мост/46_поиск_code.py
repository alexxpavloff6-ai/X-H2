# -*- coding: utf-8 -*-
"""Q3 4-й круг, шаг 46: поиск указателя на диспетчер 0x14F72C0 в данных блоков;
писатели source[0x5A8] (str [x?,#0x5a8]) — источник code выдержки."""
import struct
import sys
from pathlib import Path

HERE = Path(__file__).resolve().parent
sys.path.insert(0, str(HERE))
from q3common import load, find_bytes, dis, func_start  # noqa: E402

b0 = load('X-H2', 'old', 0)
b1 = load('X-H2', 'old', 1)
out = []
# поиск указателя 0x14F72C0 (8-byte и 4-byte LE)
for idx, b in ((0, b0), (1, b1)):
    for width, fmt in ((8, '<Q'), (4, '<I')):
        needle = struct.pack(fmt, 0x14F72C0)
        hits = find_bytes(b, needle)
        out.append(f'=== pointer 0x14F72C0 ({width}B) block{idx}: {len(hits)} ===')
        for va in hits[:20]:
            out.append(f'  {va:#x}')
out.append('')
# писатели [x?,#0x5a8]: быстрый скан слов STR (unsigned offset 32/64-bit)
# STR Wt,[Xn,#0x5a8]: 0xB9000000 imm12=0x16A ; STR Xt: 0xF9000000 imm12=0xB5
import fwcommon
sites = []
for o in range(0, len(b0.data) - 3, 4):
    w = struct.unpack_from('<I', b0.data, o)[0]
    op = w & 0xFFC00000
    imm = (w >> 10) & 0xFFF
    if (op == 0xB9000000 and imm == 0x16A) or (op == 0xF9000000 and imm == 0xB5):
        va = b0.base + o
        ins = list(fwcommon.insns(b0, va, 1))[0]
        sites.append((va, f'{ins.mnemonic} {ins.op_str}', func_start(b0, va)))
        if len(sites) >= 50:
            break
out.append(f'=== str [x?,#0x5a8] в block0 (первые {len(sites)}) ===')
for va, txt, fs in sites:
    out.append(f'  {va:#x}: {txt}  func={fs:#x}' if fs else f'  {va:#x}: {txt}')
text = '\n'.join(out)
(HERE / '4круг_поиск_code.txt').write_text(text + '\n', encoding='utf-8')
print(text[:6000])
