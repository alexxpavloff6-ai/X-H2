"""42: контекст мест, где формируются половинки 0x385/0xE170 — проверяем, не собирается ли
адрес таблицы карты регистров (0x385E170 / 0x385E14C) вручную.

Только чтение.
"""
import sys
from pathlib import Path

HERE = Path(__file__).resolve().parent
sys.path.insert(0, str(HERE))
import m4lib

sys.path.insert(0, str(m4lib.ANALYSIS / 'Сравнение_версий_2026-11-16'))
import fwcommon

spots = [('new', 1, 0x30FE7B0, 0x80), ('new', 1, 0x2E65830, 0x80),
         ('new', 1, 0x30FF380, 0x80), ('old', 1, 0x3102620, 0x80),
         ('old', 1, 0x2E69790, 0x60)]
for state, idx, va, n in spots:
    b = fwcommon.load('X-H2', state, idx)
    print(f'== {b.version} block{idx} @ {va:#x}')
    for x in fwcommon.insns(b, va, n // 4):
        print(f'  {x.address:08x}  {x.bytes.hex():<10} {x.mnemonic:<8} {x.op_str}')
