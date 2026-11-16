"""34: поиск по КОДИРОВКЕ (не по тексту capstone) записей в регистры MOVDC и сборки константы.

Ищем в блоке 1 old 5.30 / new 5.33:
  * STR/STRB/STRH/LDR/LDRH с imm12 = 0xD0/0xD4/0xD8/0xF0/0x114 (в любых регистрах);
  * MOVZ/MOVK, собирающие 0x10030001 (movz #1 + movk #0x1003<<16) и отдельные половинки
    0x0001/0x1003, а также MOVZ #0x1003;
  * любые ADRP на страницу таблицы с последующим ldr/str/add по смещению 0x100..0x240.

Печатаем сайты + окрестности. Только чтение.
"""
import json
import sys
from pathlib import Path

import numpy as np

HERE = Path(__file__).resolve().parent
sys.path.insert(0, str(HERE))
import m4lib

sys.path.insert(0, str(m4lib.ANALYSIS / 'Сравнение_версий_2026-11-16'))
import fwcommon

lines = []
out = {}


def emit(s=''):
    print(s)
    lines.append(s)


def enc_imm_str(a, offsets):
    """(сайт, (word>>10)&0xFFF) для str/strb/strh/ldr/ldrh с imm12 из offsets."""
    res = []
    for off in offsets:
        imm12 = off >> 2
        for top, kind in ((0xB9000000, 'str w'), (0xF9000000, 'str x'),
                          (0x39000000, 'strb'), (0x79000000, 'strh'),
                          (0xB9400000, 'ldr w'), (0xF9400000, 'ldr x')):
            m = ((a & 0xFFC00000) == top) & (((a >> 10) & 0xFFF) == imm12)
            for i in np.nonzero(m)[0]:
                res.append((int(i) * 4, off, kind))
    return res


OFFS = [0xD0, 0xD4, 0xD8, 0xF0, 0x114]


def dump(b, va, before=0x20, after=0x60):
    for x in fwcommon.insns(b, va - before, (before + after) // 4):
        emit(f'    {x.address:08x}  {x.bytes.hex():<10} {x.mnemonic:<8} {x.op_str}')


for state in ('old', 'new'):
    b = fwcommon.load('X-H2', state, 1)
    a = np.frombuffer(b.data[:len(b.data) & ~3], dtype='<u4')
    emit(f'== X-H2 {b.version} block1 base={b.base:#x}')
    hits = enc_imm_str(a, OFFS)
    emit(f'  STR/LDR с imm из {[hex(o) for o in OFFS]}: {len(hits)}')
    for off_i, off, kind in hits[:20]:
        emit(f'   {b.base + off_i:#x}  {kind} [x?, #{off:#x}]')
    out[state] = {'mem_hits': [{'va': hex(b.base + o), 'off': hex(of), 'kind': k}
                               for o, of, k in hits[:60]]}

    # MOVZ/MOVK: 0x1003 в старшей половине
    movz_1003 = ((a & 0xFFE0001F) == (0x52800000 | 0) ) & (((a >> 5) & 0xFFFF) == 0x1003)
    movk_hi = ((a & 0xFFE0001F) == (0x72A00000 | 0)) & (((a >> 5) & 0xFFFF) == 0x1003)
    movz_1 = ((a & 0xFFE0001F) == (0x52800000 | 0)) & (((a >> 5) & 0xFFFF) == 0x1)
    emit(f'  movz #0x1003: {int(movz_1003.sum())} {[hex(b.base + int(i) * 4) for i in np.nonzero(movz_1003)[0][:8]]}')
    emit(f'  movk #0x1003<<16: {int(movk_hi.sum())} {[hex(b.base + int(i) * 4) for i in np.nonzero(movk_hi)[0][:8]]}')
    emit(f'  movz #1: {int(movz_1.sum())}')
    out[state]['movk_1003'] = [hex(b.base + int(i) * 4) for i in np.nonzero(movk_hi)[0][:20]]
    for i in np.nonzero(movk_hi)[0][:6]:
        emit(f'   окрестности movk #0x1003<<16 @ {b.base + int(i) * 4:#x}:')
        dump(b, b.base + int(i) * 4, 0x10, 0x20)

(HERE / 'movdc_записи.txt').write_text('\n'.join(lines) + '\n', encoding='utf8')
(HERE / 'movdc_записи.json').write_text(json.dumps(out, ensure_ascii=False, indent=1), encoding='utf8')
print('saved movdc_записи.txt/.json')
