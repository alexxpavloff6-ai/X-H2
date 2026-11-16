# -*- coding: utf-8 -*-
"""E22: имена полей 0x2a0..0x2d3 (и 0x2b9 отдельно) из лог-строк сеттер-чанков."""
import sys, re, struct, json
sys.path.insert(0, r'<корень проекта>\Анализ_прошивки\Сравнение_версий_2026-11-16\E_сеттер_0x2B9')
from ecommon import *  # noqa

MODEL, STATE = 'X-H2', 'new'
b = load(MODEL, STATE, 0)
TAB, BASE = 0x174289c, 0x11e6c44
LOG = 0x133cacc


def raw_str(va, n=200):
    o = b.off(va)
    raw = b.data[o:o + n].split(b'\0')[0]
    try:
        return raw.decode('utf-8')
    except UnicodeDecodeError:
        return raw.decode('latin1')


def name_of_chunk(va, size=0xf0):
    regs = {}
    for x in all_insns(b, va, va + size):
        if x.mnemonic == '.byte':
            continue
        if x.mnemonic == 'adrp' and re.match(r'x\d+, #', x.op_str):
            reg, imm = x.op_str.split(', ')
            regs[reg] = int(imm.strip('#'), 0)
        elif x.mnemonic == 'add' and re.match(r'x\d+, x\d+, #', x.op_str):
            m = re.match(r'(x\d+), (x\d+), #(0x[0-9a-f]+|\d+)(?:, lsl #(\d+))?', x.op_str)
            if m and m.group(2) in regs:
                regs[m.group(1)] = regs[m.group(2)] + (int(m.group(3), 0) << (int(m.group(4)) if m.group(4) else 0))
        elif x.mnemonic == 'bl' and int(x.op_str.strip('#'), 16) == LOG:
            p = regs.get('x1')
            return p, (raw_str(p) if p and 0 <= b.off(p) < len(b.data) else None)
    return None, None


def chunk_of(idv):
    v = u32(b, TAB + 4 * (idv - 1))
    sv = v - (1 << 32) if v & 0x80000000 else v
    return BASE + sv * 4


rows = []
for idv in range(0x2a0, 0x2d4):
    t = chunk_of(idv)
    p, s = name_of_chunk(t)
    rows.append({'id': idv, 'chunk': t, 'fmt': p, 'name': s})
    print(f'{idv:#06x} {t:#010x} {s!r}')

open('id_names_2a0_2d3.json', 'w', encoding='utf8').write(json.dumps(rows, ensure_ascii=False, indent=1))
