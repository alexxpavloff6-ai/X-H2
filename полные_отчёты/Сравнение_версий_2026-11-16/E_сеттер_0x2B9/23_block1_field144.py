# -*- coding: utf-8 -*-
"""E23: ПОВОРОТ. В блоке 0 id 0x2B9 = 'ubNetmaskSettingManual1octet8' (сетевые настройки!).
Значит [ctx+0x3978] в блоке 1 — НЕ это свойство. Ищем в блоке 1 реальный источник
struct+0x144: кто пишет [xN,#0x144], какие getter'ы вызываются рядом, и что такое x19
в 0x30871a8.
"""
import sys, re, struct
sys.path.insert(0, r'<корень проекта>\Анализ_прошивки\Сравнение_версий_2026-11-16\E_сеттер_0x2B9')
from ecommon import *  # noqa

MODEL, STATE = 'X-H2', 'new'
b = load(MODEL, STATE, 1)

print('=== 0x30870f0..0x3087200 (контекст копирования в ctx+0x3978) ===')
dump_range(b, 0x30870f0, 0x3087240)

print('\n=== кто пишет/читает [xN,#0x144] в блоке 1 (str/strb/ldrb/ldr) ===')
rows = []
for x in all_insns(b):
    if x.mnemonic == '.byte':
        continue
    if re.search(r'\[x\d+, #0x144\]', x.op_str):
        rows.append(x)
print('всего обращений к смещению 0x144:', len(rows))
for x in rows:
    print(f'  {x.address:#x}: {x.mnemonic:8} {x.op_str}')
