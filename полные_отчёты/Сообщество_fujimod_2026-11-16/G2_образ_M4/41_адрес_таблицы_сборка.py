"""41: последняя проверка — не формируется ли адрес таблицы (0x385E14C) через movz/movk
или adrp+add с другими страницами; и не пишет ли что-то в окно таблицы.

Ищем в блоках 0-2 (old/new): movz #0xE14C, movk #0x0385, movz #0xE170, movk #0x0385,
а также u32 0x0385E14C/0x0385E170 (как low/high пары).

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

for state in ('old', 'new'):
    for idx in (0, 1, 2):
        b = fwcommon.load('X-H2', state, idx)
        a = np.frombuffer(b.data[:len(b.data) & ~3], dtype='<u4').astype(np.uint64)
        out = []
        for imm in (0xE14C, 0xE170, 0x0385, 0xE130, 0xE14D):
            for top, name in ((0x52800000, 'movz'), (0x72800000, 'movk')):
                for hw in (0, 1):
                    m = ((a & 0xFFE00000) == (top | (hw << 21))) & (((a >> 5) & 0xFFFF) == imm)
                    n = int(m.sum())
                    if n:
                        out.append(f'{name} #{imm:#06x} hw={hw}: {n} ' +
                                   str([hex(b.base + int(i) * 4) for i in np.nonzero(m)[0][:4]]))
        print(f'{state} block{idx}:')
        for row in out:
            print('   ', row)
        if not out:
            print('    ничего')
