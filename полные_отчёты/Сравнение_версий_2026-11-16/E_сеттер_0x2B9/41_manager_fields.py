# -*- coding: utf-8 -*-
"""E41: все обращения к полям менеджера 0x4daa6c0..0x4daa900 с разрешением adrp+add.
Цель: найти запись [0x4daa6e8] (указатель job) и инициализацию менеджера."""
import sys, re, struct
sys.path.insert(0, r'<корень проекта>\Анализ_прошивки\Сравнение_версий_2026-11-16\E_сеттер_0x2B9')
from ecommon import *  # noqa

BASE = 0x4daa6c0
LO, HI = 0x4daa600, 0x4daa980

for idx in (0, 1, 2):
    b = load('X-H2', 'new', idx)
    print(f'\n######## блок {idx} {b} ########')
    out = []
    for va, reg in adrp_sites(b, 0x4daa000):
        regs = {f'x{reg}': 0x4daa000}
        for x in all_insns(b, va, va + 0x60):
            if x.mnemonic == '.byte':
                continue
            m = re.match(r'(x\d+), (x\d+), #(0x[0-9a-f]+|\d+)(?:, lsl #(\d+))?$', x.op_str)
            if x.mnemonic == 'add' and m:
                d, s, imm, sh = m.groups()
                if s in regs:
                    regs[d] = regs[s] + (int(imm, 0) << (int(sh) if sh else 0))
                continue
            if x.mnemonic in ('str', 'strb', 'strh', 'stur', 'ldr', 'ldrb', 'ldrh', 'ldp', 'stp'):
                mm = re.match(r'(.+), \[([^,\]]+)(?:, #(0x[0-9a-f]+|\d+))?', x.op_str)
                if mm and mm.group(2) in regs:
                    off = int(mm.group(3), 0) if mm.group(3) else 0
                    addr = regs[mm.group(2)] + off
                    if LO <= addr < HI:
                        out.append((x.address, addr, f'{x.mnemonic} {x.op_str}'))
            if x.mnemonic in ('bl', 'b', 'ret', 'br'):
                break
    for a, addr, txt in out:
        mark = '  <<< JOB PTR' if addr == 0x4daa6e8 else ''
        print(f'  {a:#x} -> {addr:#x}: {txt}{mark}')
