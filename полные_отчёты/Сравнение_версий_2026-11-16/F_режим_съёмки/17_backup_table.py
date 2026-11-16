"""F: таблица дескрипторов полей бэкапа.

Format-строки "$BACKUP[%d]<имя>..." лежат в b0 около 0x1736000..0x1736400 и,
судя по отсутствию adrp+add-ссылок, используются через таблицу указателей.
Ищем u64, попадающие в этот диапазон, и печатаем структуру таблицы.
"""
import sys, re, json, struct, collections
sys.path.insert(0, r'<корень проекта>\Анализ_прошивки\Сравнение_версий_2026-11-16')
from fwcommon import *

b = load('X-H2', 'new', 0)
LO, HI = 0x1736000, 0x1736500
data, base = b.data, b.base
hits = []
for off in range(0, len(data) - 7, 8):
    v = struct.unpack_from('<Q', data, off)[0]
    if LO <= v < HI:
        hits.append((base + off, v))
print(f'указателей в {LO:#x}..{HI:#x}: {len(hits)}')
for a, v in hits[:8]:
    print(f'{a:#x} -> {v:#x} {b.cstr(v)}')

if hits:
    first = hits[0][0]
    print('\n-- окрестность первой таблицы --')
    for k in range(-16, 40):
        va = first + k * 8
        if not (b.base <= va < b.end):
            continue
        v = b.u64(va)
        s = b.cstr(v) if base <= v < b.end else None
        mark = ' <==' if LO <= v < HI else ''
        print(f'{va:#x}: {v:#018x}  {s or ""}{mark}')
