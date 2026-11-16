"""43: роль guard-флага 0x4c2ff14 и вызовы нашей MOVDC-функции 0x3103ff8 (new 5.33).

* bl_callers(0x3103ff8) и bl_callers(0x3103b10) в блоке 1 new;
* дизасм вокруг чтений флага (0x310247c/0x31024cc/0x31025a8) из прошлого отчёта;
* проверка, стоит ли вызов MOVDC-функции под условием по флагу/полю +0x43c.

Только чтение.
"""
import sys
from pathlib import Path

import numpy as np

HERE = Path(__file__).resolve().parent
sys.path.insert(0, str(HERE))
import m4lib

sys.path.insert(0, str(m4lib.ANALYSIS / 'Сравнение_версий_2026-11-16'))
import fwcommon

lines = []


def emit(s=''):
    print(s)
    lines.append(s)


b = fwcommon.load('X-H2', 'new', 1)
for target in (0x3103FF8, 0x3103B10, 0x310A4B8):
    callers = fwcommon.bl_callers(b, target)
    emit(f'== bl_callers({target:#x}) в 5.33 block1: {[(hex(a), k) for a, k in callers]}')

emit('\n== окрестности чтений guard-поля +0xf14 / +0x43c (new 5.33)')
for va in (0x310247C, 0x31024CC, 0x31025A8):
    emit(f'--- {va:#x}')
    for x in fwcommon.insns(b, va - 0x30, 0x18):
        mark = ' <==' if x.address == va else ''
        emit(f'  {x.address:08x}  {x.bytes.hex():<10} {x.mnemonic:<8} {x.op_str}{mark}')

emit('\n== где вызывается MOVDC-функция 0x3103ff8: контекст вызывающего')
for a, k in fwcommon.bl_callers(b, 0x3103FF8):
    emit(f'--- {k} @ {a:#x}')
    for x in fwcommon.insns(b, a - 0x40, 0x20):
        mark = ' <==' if x.address == a else ''
        emit(f'  {x.address:08x}  {x.bytes.hex():<10} {x.mnemonic:<8} {x.op_str}{mark}')

(HERE / 'флаг_и_вызовы.txt').write_text('\n'.join(lines) + '\n', encoding='utf8')
print('saved флаг_и_вызовы.txt')
