# -*- coding: utf-8 -*-
"""E20: для каждого id вытащить строку-имя поля из лога в его сеттер-чанке.
Чанки сеттера: функция 0x11e6bf0, jump-таблица 0x174289c (база 0x11e6c44), id 1..0xd69.
В чанке перед bl 0x133cacc (лог) x1 = указатель на формат-строку с именем поля.
"""
import sys, re, struct, json
sys.path.insert(0, r'<корень проекта>\Анализ_прошивки\Сравнение_версий_2026-11-16\E_сеттер_0x2B9')
from ecommon import *  # noqa

MODEL, STATE = 'X-H2', 'new'
b = load(MODEL, STATE, 0)
TAB, BASE = 0x174289c, 0x11e6c44
LOG = 0x133cacc


def name_of_chunk(va):
    regs = {}
    for x in all_insns(b, va, va + 0x400):
        if x.mnemonic == '.byte':
            continue
        if x.mnemonic == 'adrp':
            reg, imm = x.op_str.split(', ')
            regs[reg] = int(imm.strip('#'), 0)
        elif x.mnemonic == 'add' and re.match(r'x\d+, x\d+, #', x.op_str):
            m = re.match(r'(x\d+), (x\d+), #(0x[0-9a-f]+|\d+)(?:, lsl #(\d+))?', x.op_str)
            if m and m.group(2) in regs:
                val = int(m.group(3), 0) << (int(m.group(4)) if m.group(4) else 0)
                regs[m.group(1)] = regs[m.group(2)] + val
        elif x.mnemonic == 'bl' and int(x.op_str.strip('#'), 16) == LOG:
            p = regs.get('x1')
            return (p, b.cstr(p, 160) if p else None)
        elif x.mnemonic in ('ret', 'b') and x.address != va:
            pass
        if x.mnemonic == 'b':
            t = int(x.op_str.strip('#'), 16)
            if t == 0x11e6cb4:  # epilogue
                return (None, None)
    return (None, None)


rows = []
for idv in range(0x2a0, 0x2d4):
    v = u32(b, TAB + 4 * (idv - 1))
    sv = v - (1 << 32) if v & 0x80000000 else v
    t = BASE + sv * 4
    p, s = name_of_chunk(t)
    rows.append({'id': idv, 'chunk': t, 'fmt': p, 'name': s})
    print(f'{idv:#06x} chunk {t:#x} fmt {p and hex(p)}  {s!r}')

json.dumps(rows)
open('id_names_2a0_2d3.json', 'w', encoding='utf8').write(json.dumps(rows, ensure_ascii=False, indent=1))
