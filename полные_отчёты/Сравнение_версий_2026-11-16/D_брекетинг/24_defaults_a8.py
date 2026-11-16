# -*- coding: utf-8 -*-
"""D2: таблица значений параметров по умолчанию в блоке 0 и кто пишет blob[0xa8].

Блок 0: функция инициализации параметров обнуляет blob и заливает значения из таблицы
записей по 4 байта: u16 id, u8 value, u8 pad (id == 0xFFFE — конец).
Адреса таблиц (найдены по общему байтовому образу первых записей):
  X-H2  5.33: 0x1AC3CB8 (42 023 записи)
  X-H2S 7.31: 0x1DE25F8 (41 993)
  X-T5  4.32: 0x1AB2278 (41 751)
Скрипт печатает id 0xa8 и его соседей, а также ищет записи 0xa8 через set_u8.
"""
import sys, re, struct
sys.path.insert(0, r'<корень проекта>\Анализ_прошивки\Сравнение_версий_2026-11-16\D_брекетинг')
from dhelp import *  # noqa

TABLES = {'X-H2': 0x1ac3cb8, 'X-H2S': 0x1de25f8, 'X-T5': 0x1ab2278}

def parse_defaults(model, table_va):
    b = load(model, 'new', 0)
    rows = []
    off = b.off(table_va)
    while off + 4 <= len(b.data):
        pid, val, pad = struct.unpack_from('<HBB', b.data, off)
        if pid == 0xfffe:
            break
        rows.append((pid, val))
        off += 4
    return b, rows

for model, addr in TABLES.items():
    b, rows = parse_defaults(model, addr)
    d = dict(rows)
    print(f'{model}: таблица {addr:#x}, записей {len(rows)}, id 0xa8 = {d.get(0xa8)}')
    print('   соседние id:', {hex(k): d.get(k) for k in range(0xa0, 0xb0)})

# --- кто читает и кто пишет 0xa8 ---
MOV_A8 = 0x52800000 | (0xa8 << 5)
print('\nвсе `mov w0,#0xa8` + bl в блоке 1 (чтения и записи):')
for model in MODELS:
    b = load(model, 'new', 1)
    n = 0
    for o in range(0, len(b.data) - 8, 4):
        if struct.unpack_from('<I', b.data, o)[0] != MOV_A8:
            continue
        w1 = struct.unpack_from('<I', b.data, o + 4)[0]
        if (w1 & 0xfc000000) != 0x94000000:
            continue
        n += 1
    print(f'  {model}: {n} мест')
