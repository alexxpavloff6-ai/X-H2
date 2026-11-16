# -*- coding: utf-8 -*-
"""E6: найти диспетчер, чья jump-таблица указывает в район 0x128c300..0x128c800.

Логика: для каждого br ищем рядом adr (база таблицы) и add x,base,wN,sxth#2;
проверяем, попадает ли диапазон целей [base-32768*4, base+32767*4] в наш район.
"""
import sys, re, struct
sys.path.insert(0, r'<корень проекта>\Анализ_прошивки\Сравнение_версий_2026-11-16\E_сеттер_0x2B9')
from ecommon import *  # noqa

MODEL, STATE = 'X-H2', 'new'
NEEDLE_LO, NEEDLE_HI = 0x128c300, 0x128c800

for idx in (0, 1):
    b = load(MODEL, STATE, idx)
    print(f'\n######## блок {idx} base={b.base:#x} ########')
    hist = []
    for x in all_insns(b):
        if x.mnemonic == '.byte':
            continue
        if x.mnemonic == 'br':
            # ищем в истории adr и add ... sxth/sxtb
            base_tab = None
            scale = None
            for y in reversed(hist[-8:]):
                if y.mnemonic == 'adr':
                    base_tab = int(re.search(r'#0x([0-9a-f]+)', y.op_str).group(1), 16)
                    break
                m = re.search(r'sxt([bh]) #2', y.op_str)
                if m:
                    scale = m.group(1)
            if base_tab is None:
                continue
            if scale == 'h':
                lo, hi = base_tab - 0x8000 * 4, base_tab + 0x7fff * 4
            elif scale == 'b':
                lo, hi = base_tab - 0x80 * 4, base_tab + 0x7f * 4
            else:
                lo, hi = base_tab - 0x80000000, base_tab + 0x7fffffff
            if lo <= NEEDLE_HI and hi >= NEEDLE_LO:
                print(f'\n--- br {x.address:#x}, база таблицы adr={base_tab:#x}, scale={scale}')
                print(f'    диапазон целей {hex(lo)}..{hex(hi)}')
                for y in hist[-10:]:
                    print(f'   {y.address:x}: {y.mnemonic:8} {y.op_str}')
        hist.append(x)
