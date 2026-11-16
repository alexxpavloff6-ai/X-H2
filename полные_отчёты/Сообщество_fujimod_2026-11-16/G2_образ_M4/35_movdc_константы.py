"""35: корректный поиск сборки 0x10030001 и арифметики адресов MOVDC.

В прошлом скрипте маски MOVZ/MOVK были неверны (требовали Rd=0). Здесь:
  * MOVZ/MOVK 32-бит: (word & 0xFFE00000) == 0x52800000/0x72800000 | (hw<<21), imm16 = (w>>5)&0xFFFF;
  * ищем movz/movk c imm16 = 0x1003, 0x0001, 0x0003 и любые пары, дающие 0x10030001;
  * `add xD, xN, #0xd0/0xd8/0xf0` и `mov wD, #0xd0/...` — арифметика смещений;
  * для найденных пар movz/movk печатаем окрестности.

Только чтение.
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


def scan(state):
    b = fwcommon.load('X-H2', state, 1)
    a = np.frombuffer(b.data[:len(b.data) & ~3], dtype='<u4').astype(np.uint64)
    emit(f'== X-H2 {b.version} block1 base={b.base:#x}')

    def movx(top, hw, imm16):
        m = ((a & 0xFFE00000) == (top | (hw << 21))) & (((a >> 5) & 0xFFFF) == imm16)
        return [b.base + int(i) * 4 for i in np.nonzero(m)[0]]

    for imm in (0x1003, 0x0001, 0x0003):
        for hw in (0, 1, 2, 3):
            hz = movx(0x52800000, hw, imm)
            hk = movx(0x72800000, hw, imm)
            if hz or hk:
                emit(f'  imm16={imm:#06x} hw={hw}: movz={len(hz)} {[hex(x) for x in hz[:6]]} | '
                     f'movk={len(hk)} {[hex(x) for x in hk[:6]]}')

    # ADD immediate: 0x91000000 | (imm12<<10) | (Rn<<5) | Rd
    for off in (0xD0, 0xD8, 0xF0, 0x114):
        imm12 = off
        m = ((a & 0xFFC00000) == 0x91000000) & (((a >> 10) & 0xFFF) == imm12)
        hits = [b.base + int(i) * 4 for i in np.nonzero(m)[0]]
        emit(f'  add x?, x?, #{off:#x}: {len(hits)} {[hex(x) for x in hits[:10]]}')
        out.setdefault(state, {})[f'add_{off:x}'] = [hex(x) for x in hits[:40]]

    # MOV (wide imm) wD, #imm  -> 0x52800000 family уже покрыт; ADR/other не нужно
    return b


def dump(b, va, before=0x20, after=0x60):
    for x in fwcommon.insns(b, va - before, (before + after) // 4):
        emit(f'    {x.address:08x}  {x.bytes.hex():<10} {x.mnemonic:<8} {x.op_str}')


for state in ('old', 'new'):
    b = scan(state)
    # окрестности всех movk #0x1003 (hw=1) и movz #0x1003
    a = np.frombuffer(b.data[:len(b.data) & ~3], dtype='<u4').astype(np.uint64)
    m = (((a & 0xFFE00000) == 0x72A00000) | ((a & 0xFFE00000) == 0x52802000)) & \
        (((a >> 5) & 0xFFFF) == 0x1003)
    hits = [b.base + int(i) * 4 for i in np.nonzero(m)[0]]
    emit(f'  всего movz/movk #0x1003 (любой hw): {len(hits)} {[hex(x) for x in hits[:8]]}')
    for h in hits[:4]:
        dump(b, h, 0x28, 0x50)

(HERE / 'movdc_константы.txt').write_text('\n'.join(lines) + '\n', encoding='utf8')
(HERE / 'movdc_константы.json').write_text(json.dumps(out, ensure_ascii=False, indent=1), encoding='utf8')
print('saved movdc_константы.txt/.json')
