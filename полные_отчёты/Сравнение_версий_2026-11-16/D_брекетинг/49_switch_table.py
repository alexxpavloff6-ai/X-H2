# -*- coding: utf-8 -*-
"""D6: декодирование jump-таблицы switch в 0x2d3a500 (X-H2 5.33, блок 1).

Группа 0x300:
  0x2d3a928: sub w0,w0,#0x300 ; cmp w0,#0xaa ; b.hi default
  0x2d3a934: adrp x1,0x33bd000 ; add x1,x1,#0x468   (таблица 0x33BD468)
  0x2d3a93c: ldrh w0,[x1,w0,uxtw #1]
  0x2d3a940: adr x1,0x2d3a94c
  0x2d3a944: add x0,x1,w0,sxth #2
  0x2d3a948: br x0
Тело каждого case: mov w19,#id ; b 0x2d3a958 (orr w19,#0x4000).
Скрипт: для каждого кода 0x300..0x3aa вычисляет тело, извлекает id, печатает
code -> id и отдельно код(ы), дающие 0x2b9.
"""
import sys, re, struct
sys.path.insert(0, r'<корень проекта>\Анализ_прошивки\Сравнение_версий_2026-11-16\D_брекетинг')
from dhelp import *  # noqa

b = load('X-H2', 'new', 1)
TABLE = 0x33bd468
BASE = 0x2d3a94c
N = 0xab

def body_id(addr):
    """Первый mov w19,#imm по адресу тела."""
    for x in insns(b, addr, 2):
        m = re.match(r'w19, #(0x[0-9a-f]+|\d+)', x.op_str)
        if x.mnemonic == 'mov' and m:
            return int(m.group(1), 0)
        if x.mnemonic == 'b':
            return None
    return None

print('idx  code    target   id')
hits_2b9 = []
rows = []
for i in range(N + 1):
    o = b.off(TABLE + i * 2)
    half = struct.unpack_from('<h', b.data, o)[0]
    tgt = BASE + half * 4
    cid = body_id(tgt)
    code = 0x300 + i
    rows.append((code, tgt, cid))
    if cid == 0x2b9:
        hits_2b9.append(code)
    if i < 12 or (cid is not None and 0x2ac <= cid <= 0x2c0):
        print(f'{i:4d} {code:#06x} {tgt:#08x}  {cid if cid is None else hex(cid)}')

print('\nкоды, дающие 0x2b9:', [hex(c) for c in hits_2b9])
print('всего кодов в группе:', len(rows))
from collections import Counter
cnt = Counter(cid for _, _, cid in rows if cid is not None)
print('распределение id (топ-20):', cnt.most_common(20))

# соседи найденного кода
for c in hits_2b9:
    i = c - 0x300
    print(f'\nсоседние коды вокруг {c:#x}:')
    for j in range(max(0, i - 5), min(len(rows), i + 6)):
        print(f'   {rows[j][0]:#06x} -> {rows[j][2] if rows[j][2] is None else hex(rows[j][2])} (тело {rows[j][1]:#x})')
