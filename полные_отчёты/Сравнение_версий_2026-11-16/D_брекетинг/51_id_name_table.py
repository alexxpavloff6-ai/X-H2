# -*- coding: utf-8 -*-
"""D6: таблица соответствия «свойство -> UI_SETP_ имя» в блоке 0 (X-H2 5.33).

Строки UI_SETP_* живут в блоке 0 (0x164bed0…). Ищем 8/4-байтовые ссылки на них,
смотрим формат записи (возможно {u16 id, u16 ?, u32 nameidx} или {u32 ptr, u32 id})
и ищем запись с id 0x2B9.
"""
import sys, re, struct
sys.path.insert(0, r'<корень проекта>\Анализ_прошивки\Сравнение_версий_2026-11-16\D_брекетинг')
from dhelp import *  # noqa

b = load('X-H2', 'new', 0)
STR = 0x164bed0          # 'UI_SETP_FWUP_NOTICE_FW_MINOR_VER'
for fmt, name in (('<Q', 'u64'), ('<I', 'u32')):
    pat = struct.pack(fmt, STR)
    hits = find_bytes(b, pat)
    print(f'{name} ссылок на {STR:#x}: {len(hits)}: {[hex(h) for h in hits][:10]}')
    for h in hits[:4]:
        o = b.off(h)
        seg = b.data[max(0, o - 32):o + 48]
        print(f'  {h:#x}: {seg.hex(" ")}')

# Если нашли таблицу — ищем рядом записи с id 0x2B9 (u16 или u32).
print('\n--- поиск u32 0x2b9 рядом с указателями на UI_SETP (в .rodata блока 0) ---')
# соберём адреса всех UI_SETP строк
strs = [b.base + m.start() for m in re.finditer(rb'UI_SETP_[A-Z0-9_]{3,}', b.data)]
print('строк UI_SETP:', len(strs))
u32_2b9 = []
pat = struct.pack('<I', 0x2b9)
start = 0
while True:
    i = b.data.find(pat, start)
    if i < 0:
        break
    u32_2b9.append(b.base + i)
    start = i + 1
print('u32 0x2b9 в блоке 0:', len(u32_2b9), [hex(a) for a in u32_2b9][:20])
for a in u32_2b9[:10]:
    o = b.off(a)
    seg = b.data[max(0, o - 24):o + 32]
    print(f'  {a:#x}: {seg.hex(" ")}')
