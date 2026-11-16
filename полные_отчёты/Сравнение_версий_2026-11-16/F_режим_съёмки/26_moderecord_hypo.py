"""F: гипотеза S+0 == MODE_RECORD (enum 0..0x2D: SP/P/S/A/M/ADV/HDR/MOTIONJPEG).

Ищем в b1 чтения [S+0] (0x244eb20) и в пределах 12 инструкций cmp того же
регистра с «характерными» значениями MODE_RECORD: 0x1d,0x1e,0x1f,0x20,
0x21,0x22,0x23,0x24,0x2c,0x2d.
"""
import sys, re, json, struct, collections
sys.path.insert(0, '<корень проекта>/Анализ_прошивки/Сравнение_версий_2026-11-16/F_режим_съёмки')
from fhelp import *

S, PAGE = 0x244eb20, 0x244e000
MARK = {0x1d, 0x1e, 0x1f, 0x20, 0x21, 0x22, 0x23, 0x24, 0x2c, 0x2d}


def reg(t):
    m = re.fullmatch(r'[xw](\d+)', t.strip())
    return f'x{m.group(1)}' if m else None


for idx in (1,):
    b = load('X-H2', 'new', idx)
    found = []
    for va, r0 in adrp_sites(b, PAGE):
        r = f'x{r0}'
        for x in insns(b, va + 4, 3):
            m = re.fullmatch(r'(x\d+), (x\d+), #(-?0x[0-9a-f]+|-?\d+)', x.op_str)
            if x.mnemonic == 'add' and m and m.group(2) == r and int(m.group(3), 0) == 0xb20:
                base = reg(m.group(1))
                # ищем ldr [base]
                for y in insns(b, x.address + 4, 40):
                    if y.mnemonic.startswith('ldr') and f'[{base}]' in y.op_str and y.op_str.endswith(f'[{base}]'):
                        dst = reg(y.op_str.split(',')[0])
                        for z in insns(b, y.address + 4, 12):
                            if z.mnemonic == 'cmp':
                                mm = re.fullmatch(rf'{dst}, #(0x[0-9a-f]+|\d+)', z.op_str)
                                if mm and int(mm.group(1), 0) in MARK:
                                    found.append((y.address, int(mm.group(1), 0), z.address))
                            if z.mnemonic in ('bl', 'b', 'ret'):
                                break
                    if y.mnemonic in ('bl', 'ret', 'b'):
                        break
                break
            if x.mnemonic in ('bl', 'b', 'ret', 'br'):
                break
    print(f'== b{idx}: чтений S+0 со сравнением на MODE_RECORD-константы: {len(found)}')
    for site, v, cs in found:
        print(f'   ldr {site:x} -> cmp #{v:#x} @ {cs:x}')
        print(dis(b, site - 8, 12).replace('\n', '\n      '))
