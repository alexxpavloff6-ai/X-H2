"""F: property id -> код-обработчик -> смещение поля в записи настроек.

Ядро 0x12aa788 (X-H2 b0) для id 1..0xd6a использует jump-таблицу
0x1745e70 (s32, относительно 0x12aa7dc): target = 0x12aa7dc + off*4.
Каждый case читает/пишет settings_base(0x2624a88) + slot*0x12768 + <offset>.

Декодируем нужные id и печатаем смещение и размер (ldrb/ldrh/ldr).
"""
import sys, re, struct
sys.path.insert(0, '<корень проекта>/Анализ_прошивки/Сравнение_версий_2026-11-16/F_режим_съёмки')
from fhelp import *

CASES = {
    'X-H2': dict(b0=0, core=0x12aa788, tbl=0x1745e70, anchor=0x12aa7dc,
                 ids={0x979: 'prop 0x979', 0x978: 'prop 0x978', 0x9ff: 'prop 0x9ff',
                      0x2b9: 'prop 0x2B9 (режим)', 0x358: 'prop 0x358', 0x90a: 'prop 0x90a',
                      0xd: 'prop 0x0d', 0x12b: 'prop 0x12b'}),
}

b = load('X-H2', 'new', 0)
core, tbl, anchor = 0x12aa788, 0x1745e70, 0x12aa7dc
for pid in (0x979, 0x2b9, 0x358, 0x90a, 0xd, 0x12b):
    k = pid - 1
    off = struct.unpack_from('<i', b.data, b.off(tbl) + k * 4)[0]
    tgt = anchor + off * 4
    print(f'id {pid:#x}: off={off} -> case {tgt:#x}')
    print(dis(b, tgt, 8))
    print('---')
