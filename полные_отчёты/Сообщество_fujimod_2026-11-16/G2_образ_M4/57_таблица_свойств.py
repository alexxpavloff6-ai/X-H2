"""57: таблица свойств: резолвер 0x5460C, запись для id=0x4C (имя/размер), и продолжение геттера.

Цель — понять, что за свойство 0x4C (0x168 байт) и как называется поле +0x74.
Только чтение.
"""
import re
import struct
import sys
from pathlib import Path

import numpy as np

HERE = Path(__file__).resolve().parent
sys.path.insert(0, str(HERE))
import m4lib

sys.path.insert(0, str(m4lib.ANALYSIS / 'Сравнение_версий_2026-11-16'))
import fwcommon

b = fwcommon.load('X-H2', 'new', 0)
lines = []


def emit(s=''):
    print(s)
    lines.append(s)


def dump(lo, hi, tag):
    emit(f'--- {tag} [{lo:#x}..{hi:#x})')
    for x in fwcommon.insns(b, lo, (hi - lo) // 4):
        emit(f'  {x.address:08x}  {x.bytes.hex():<10} {x.mnemonic:<8} {x.op_str}')


dump(0x14C63E0, 0x14C6440, 'геттер, продолжение')
dump(0x5460C, 0x54690, 'резолвер свойств 0x5460C')

# ищем в резолвере ADRP на таблицу и её окрестности
for x in fwcommon.insns(b, 0x5460C, 0x30):
    m = re.search(r'adrp\s+x\d+, #(0x[0-9a-f]+)', f'{x.mnemonic} {x.op_str}')
    if m:
        emit(f'  ADRP в резолвере: {x.address:#x} → {m.group(1)}')

(HERE / 'таблица_свойств.txt').write_text('\n'.join(lines) + '\n', encoding='utf8')
print('saved таблица_свойств.txt')
