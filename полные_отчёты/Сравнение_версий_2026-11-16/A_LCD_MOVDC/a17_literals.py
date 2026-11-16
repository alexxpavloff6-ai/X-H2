# -*- coding: utf-8 -*-
"""Шаг 17: поиск literal-pool ссылок (u64) на флаг и поле-источник.

ADRP-скан не видит загрузку адреса из литерала (ldr xN, =addr). Ищем 8-байтовые
вхождения адресов в блоках 0/1/2 и печатаем окрестности (что за код рядом).
"""
import sys, os, struct
sys.path.insert(0, r'<корень проекта>\Анализ_прошивки\Сравнение_версий_2026-11-16')
from fwcommon import *  # noqa

ADDRS = {
    ('X-H2', 'old'): [0x4c33f14, 0x4c3f26c, 0x4c3f104],
    ('X-H2', 'new'): [0x4c2ff14, 0x4c3b26c, 0x4c3b104],
    ('X-H2S', 'old'): [0x4ba8f0c, 0x4bb4064, 0x4bb3efc],
    ('X-H2S', 'new'): [0x4ba8f0c, 0x4bb4064, 0x4bb3efc],
    ('X-T5', 'old'): [0x4ab72c4, 0x4ac29b4, 0x4ac2800],
    ('X-T5', 'new'): [0x4ab72c4, 0x4ac29b4, 0x4ac2800],
}

if __name__ == '__main__':
    for m in MODELS:
        for st in ('old', 'new'):
            print(f'=== {m} {st}')
            for a in ADDRS[(m, st)]:
                pat = struct.pack('<Q', a)
                total = 0
                for blk in (1, 2, 0):
                    b = load(m, st, blk)
                    hits = find_bytes(b, pat)
                    for h in hits:
                        total += 1
                        print(f'  {a:#x} b{blk} @{h:#x}')
                        if blk == 1:
                            print('     ' + '\n     '.join(
                                f'{y.address:x}: {y.mnemonic} {y.op_str}'
                                for y in insns(b, h - 24, 14)))
                if not total:
                    print(f'  {a:#x}: literal-ссылок нет')
