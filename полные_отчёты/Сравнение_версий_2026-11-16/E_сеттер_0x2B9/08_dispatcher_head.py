# -*- coding: utf-8 -*-
"""E8: вход функции-диспетчера (switch id 1..0xd69, case 0x2b9 -> 0x128c558),
её аргументы, вызывающие, и что делает 0x11da370."""
import sys, re, struct
sys.path.insert(0, r'<корень проекта>\Анализ_прошивки\Сравнение_версий_2026-11-16\E_сеттер_0x2B9')
from ecommon import *  # noqa

MODEL, STATE = 'X-H2', 'new'
b = load(MODEL, STATE, 0)
DISP = 0x11e6c40

print('=== окрестность 0x11e6900..0x11e6c60 ===')
dump_range(b, 0x11e6a60, 0x11e6c60)

# начало функции: назад от 0x11e6c40
st = find_prologue(b, DISP, limit=0x2000)
print('\nprologue:', hex(st) if st else None)
if st:
    print(dis(b, st, 20))
    print('\ncallers of', hex(st), ':')
    for a, k in bl_callers(b, st):
        print(f'\n--- call {a:#x} ({k}) ---')
        dump_range(b, a - 0x50, a + 8)

print('\n=== 0x11da370: что это ===')
print(dis(b, 0x11da370, 40))
print('callers count:', len(bl_callers(b, 0x11da370)))
