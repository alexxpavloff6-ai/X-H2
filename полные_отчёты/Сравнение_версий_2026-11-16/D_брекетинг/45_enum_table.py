# -*- coding: utf-8 -*-
"""D5: поиск таблицы enum кодов режима и ASCII-названий режимов (BKT/BRACKET/DRIVE/...).

1) Байтовые прогоны 1D..2D / 21..2D / 2A..2D в блоках 0/1 (возможная таблица enum).
2) ASCII-строки с BKT/BRACKET/DRIVE/FILM/HDR/MULTI/CLARITY и адреса; для найденных —
   кто ссылается (adrp+add) в блоке.
"""
import sys, re, struct
sys.path.insert(0, r'<корень проекта>\Анализ_прошивки\Сравнение_версий_2026-11-16\D_брекетинг')
from dhelp import *  # noqa

RUNS = [bytes(range(0x1d, 0x2e)), bytes(range(0x21, 0x2e)), bytes(range(0x2a, 0x2e)),
        bytes(range(0x1d, 0x25)), bytes(range(0x20, 0x2e))]

for model, idx in (('X-H2', 0), ('X-H2', 1)):
    b = load(model, 'new', idx)
    print(f'\n===== {model} new b{idx}: байтовые прогоны')
    for run in RUNS:
        hits = find_bytes(b, run)
        if hits:
            print(f'  {run.hex()}: {[hex(h) for h in hits][:8]}')
    pats = [b'BRACKET', b'BKT', b'DRIVE', b'FILM_SIM', b'FILM SIM', b'MULTI', b'CLARITY',
            b'PIXEL_SHIFT', b'PIXEL SHIFT', b'ISO_BKT', b'FSIM']
    for pat in pats:
        addrs = [b.base + m.start() for m in re.finditer(re.escape(pat), b.data)]
        if addrs:
            print(f'  {pat!r}: {[hex(a) for a in addrs][:8]} (всего {len(addrs)})')
            for a in addrs[:2]:
                print('     ', repr(b.cstr(a, 70)))
