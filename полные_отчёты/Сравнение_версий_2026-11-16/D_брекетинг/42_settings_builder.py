# -*- coding: utf-8 -*-
"""D4: кто строит структуру-настройки, из которой копируется режим в ctx+0x3978.

Копировщик 0x30871ac берёт [settings+0x144] → ctx+0x3978; рядом копируются
settings+0x130,0x134,0x140. Ищем в блоках 0/1 последовательные записи
+0x130/+0x134/+0x140/+0x144 в одну структуру и печатаем контекст (источник).
"""
import sys, re, struct
sys.path.insert(0, r'<корень проекта>\Анализ_прошивки\Сравнение_версий_2026-11-16\D_брекетинг')
from dhelp import *  # noqa

def scan(model, state, idx, lo=None, hi=None):
    b = load(model, state, idx)
    hits = []
    last = {}
    for x in all_insns(b):
        if x.mnemonic == '.byte':
            continue
        m = re.search(r'\[(x\d+), #0x(1[0-9a-f]{2})\]', x.op_str)
        if x.mnemonic in ('str', 'strh', 'strb') and m:
            base, off = m.group(1), int(m.group(2), 16)
            if off in (0x130, 0x134, 0x140, 0x144):
                last[(base, off)] = (x.address, f'{x.mnemonic} {x.op_str}')
            # структура «одна»: 0x140 и 0x144 подряд
            if off == 0x144 and (base, 0x140) in last and x.address - last[(base, 0x140)][0] <= 0x40:
                hits.append((x.address, base,
                             [last[(base, 0x130)][1] if (base, 0x130) in last else None,
                              last[(base, 0x134)][1] if (base, 0x134) in last else None,
                              last[(base, 0x140)][1], last[(base, 0x144)][1]]))
    return b, hits

for m, st in (('X-H2', 'new'),):
    for idx in (0, 1):
        b, hits = scan(m, st, idx)
        print(f'\n=== {m} {st} b{idx}: кандидатов {len(hits)}')
        for a, base, fields in hits[:20]:
            print(f'  {a:#x} (база {base}): {fields}')
            print(dis(b, a - 0x28, 14).replace('\n', '\n      '))
