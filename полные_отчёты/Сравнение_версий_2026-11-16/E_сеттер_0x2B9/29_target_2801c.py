# -*- coding: utf-8 -*-
"""E29: точечный поиск записи blob[0x2801C]:
- идиома add w0,wX,#0x28,lsl#12 + add w0,w0,#0x1c (+0x13 при базе 9) перед get/set;
- прямые strb в [blob + 0x2801c] через указатель;
- значение 0x2c рядом с такими записями."""
import sys, re, struct
sys.path.insert(0, r'<корень проекта>\Анализ_прошивки\Сравнение_версий_2026-11-16\E_сеттер_0x2B9')
from ecommon import *  # noqa

for idx in (0, 1):
    b = load('X-H2', 'new', idx)
    print(f'\n######## блок {idx} ########')
    hits = []
    ins = [x for x in all_insns(b) if x.mnemonic != '.byte']
    for i, x in enumerate(ins):
        if x.mnemonic == 'add' and re.match(r'w\d+, w\d+, #0x28, lsl #12$', x.op_str):
            seq = ins[i + 1:i + 4]
            for y in seq:
                if y.mnemonic == 'add':
                    m = re.search(r', #(0x[0-9a-f]+|\d+)$', y.op_str)
                    if not m:
                        continue
                    immv = int(m.group(1), 0)
                    if immv in (0x1c, 0x13, 0x23):
                        hits.append((x.address, immv, ins[i:i + 6]))
                        break
    print('кандидатов:', len(hits))
    for a, immv, seq in hits[:20]:
        print(f'\n--- {a:#x} (off {immv:#x})')
        for y in seq:
            print(f'   {y.address:x}: {y.mnemonic:8} {y.op_str}')
