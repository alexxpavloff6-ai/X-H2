"""F: найти таблицу/резолвер enum DRIVEMODE.

Строки BKUP_DOTLCD_POWOFF_DRIVEMODE_* (b0 X-H2 5.33, 0x167c520..0x167c9a0) —
похоже, полный enum режимов привода. Ищем:
  * u64-указатели на них (таблица в данных),
  * ADRP+ADD ссылки (резолвер в коде).
"""
import sys, re, json, struct, collections
sys.path.insert(0, r'<корень проекта>\Анализ_прошивки\Сравнение_версий_2026-11-16')
from fwcommon import *
import fwcommon

b = load('X-H2', 'new', 0)
LO, HI = 0x167c500, 0x167c9c0
# собрать строки
addrs = {}
a = LO
while a < HI:
    s = b.cstr(a)
    if s:
        addrs[a] = s
        a += (len(s) + 8) & ~7
    else:
        a += 8
for x, s in addrs.items():
    print(f'{x:#x} {s}')

print('\n-- u64-указатели --')
data, base = b.data, b.base
tbl = []
for off in range(0, len(data) - 7, 8):
    v = struct.unpack_from('<Q', data, off)[0]
    if v in addrs:
        tbl.append((base + off, v))
print(f'найдено {len(tbl)}')
if tbl:
    t0 = tbl[0][0]
    print('окрестность первой таблицы:')
    for k in range(-4, len(addrs) + 4):
        va = t0 + k * 8
        try:
            v = b.u64(va)
        except Exception:
            break
        print(f'  {va:#x}: {v:#x}  {b.cstr(v) or ""}')

print('\n-- adrp+add ссылки в коде --')
tgt = set(addrs)
for va, w in iter_words(b):
    if (w & 0x9f000000) != 0x90000000:
        continue
    t = fwcommon._adrp_target(w, va)
    if not t:
        continue
    page, reg = t
    r = f'x{reg}'
    for x in insns(b, va + 4, 3):
        m = re.fullmatch(r'(x\d+), (x\d+), #(-?0x[0-9a-f]+|-?\d+)', x.op_str)
        if x.mnemonic == 'add' and m and m.group(2) == r:
            t2 = page + int(m.group(3), 0)
            if t2 in tgt:
                print(f'  {x.address:#x} -> {t2:#x} "{addrs[t2]}"')
            break
