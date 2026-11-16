"""51: проверяем адреса структур params (pending/current) и memcpy вокруг 0x31015B4,
а также кто читает/пишет поле +0x74 в этих структурах.

Только чтение.
"""
import json
import re
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


def win(b, va, before=0x40, after=0x80):
    for x in fwcommon.insns(b, va - before, (before + after) // 4):
        mark = ' <==' if x.address == va else ''
        emit(f'  {x.address:08x}  {x.bytes.hex():<10} {x.mnemonic:<8} {x.op_str}{mark}')


b = fwcommon.load('X-H2', 'new', 1)
emit('== окрестности memcpy pending→current (0x31015B4, 5.33 block1)')
win(b, 0x31015B4, 0x40, 0x60)

emit('\n== окрестности apply-функции с флагом (0x310247C..0x31025A8) — начало функции')
# найдём начало функции вокруг 0x310247c
fs = fwcommon.func_start(b, 0x310247C)
emit(f'  func_start(0x310247c) = {hex(fs) if fs else None}')
if fs:
    win(b, fs, 0, 0x60)

emit('\n== все ADRP+ADD, дающие базы 0x4C2FE.. / 0x4C3B1.. (структуры params) в блоке 1 new')
a = np.frombuffer(b.data[:len(b.data) & ~3], dtype='<u4')
adrp_idx = np.nonzero((a & 0x9f000000) == 0x90000000)[0]
from capstone import Cs, CS_ARCH_ARM64, CS_MODE_LITTLE_ENDIAN
cs = Cs(CS_ARCH_ARM64, CS_MODE_LITTLE_ENDIAN)
targets = {}
for i in adrp_idx:
    va = b.base + int(i) * 4
    seq = fwcommon.insns(b, va, 3)
    if len(seq) < 2:
        continue
    x = seq[1]
    if x.mnemonic == 'add' and '#' in x.op_str:
        try:
            imm = int(x.op_str.split('#')[1], 0)
        except ValueError:
            continue
        page = 0
        m = re.search(r'#(0x[0-9a-f]+)', seq[0].op_str)
        if not m:
            continue
        page = int(m.group(1), 0)
        tgt = page + imm
        if 0x4C2F000 <= tgt < 0x4C40000:
            targets.setdefault(tgt, []).append(hex(va))
emit(f'  уникальных баз в 0x4C2F000..0x4C40000: {len(targets)}')
for t, sites in sorted(targets.items()):
    emit(f'   {t:#x}: {len(sites)} сайтов {sites[:5]}')

(HERE / 'структуры_params.txt').write_text('\n'.join(lines) + '\n', encoding='utf8')
print('saved структуры_params.txt')
