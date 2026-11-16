"""F: для X-H2S 7.31 и X-T5 4.32 найти ядро property-get и декодировать
id -> смещение поля настроек (аналог 27_prop_to_offset.py для X-H2).

Ищем `sub w0,w0,#1; cmp w0,#0xd69` (X-H2), иначе — `cmp w0,#<N>` с последующим
`adrp+add` таблицей s32 и `adr+add+br`.
"""
import sys, re, struct
sys.path.insert(0, '<корень проекта>/Анализ_прошивки/Сравнение_версий_2026-11-16/F_режим_съёмки')
from fhelp import *


def find_core(b):
    """Найти (core, table, anchor) для property-id диспетчера в b0."""
    xs = list(insns(b, b.base, 0))
    return None


def find_core2(b):
    # потоково ищем пары
    data, base = b.data, b.base
    for va, w in iter_words(b):
        # sub w0,w0,#1 == 0x51000400
        if w != 0x51000400:
            continue
        n = insns(b, va + 4, 1)
        if not n or n[0].mnemonic != 'cmp' or not n[0].op_str.startswith('w0, #0x'):
            continue
        lim = int(n[0].op_str.split('#')[1], 0)
        # далее adrp+add+ldr w0,[x1,w0,uxtw#2]+adr+add+br
        seq = insns(b, va + 8, 8)
        tbl = anchor = None
        for i, x in enumerate(seq):
            if x.mnemonic == 'adrp':
                page = int(x.op_str.split('#')[1], 0)
                reg = x.op_str.split(',')[0]
                y = seq[i + 1] if i + 1 < len(seq) else None
                m = re.fullmatch(r'(x\d+), (x\d+), #(-?0x[0-9a-f]+|-?\d+)', y.op_str) if y else None
                if y and y.mnemonic == 'add' and m and m.group(2) == reg:
                    tbl = page + int(m.group(3), 0)
            if x.mnemonic == 'adr':
                anchor = int(x.op_str.split('#')[1], 0)
        if tbl and anchor:
            return va - 0x8, lim, tbl, anchor
    return None


def decode(b, tbl, anchor, ids, pre=0x18):
    out = {}
    for pid in ids:
        k = pid - 1
        off = struct.unpack_from('<i', b.data, b.off(tbl) + k * 4)[0]
        tgt = anchor + off * 4
        line = None
        for x in insns(b, tgt, 20):
            m = re.fullmatch(r'(w|x)(\d+), \[x\d+, #(0x[0-9a-f]+|\d+)\]', x.op_str)
            if m and x.mnemonic.startswith('ldr'):
                line = (x.address, f'{x.mnemonic} {x.op_str}', int(m.group(3), 0))
                break
        # плюс предшествующий add #1,lsl#12
        shift = 0
        for x in insns(b, tgt, 20):
            if x.mnemonic == 'add' and 'lsl #12' in x.op_str and '#0x1,' in x.op_str.replace(', ', ','):
                shift = 0x1000
            if x.address == (line[0] if line else 0):
                break
        out[pid] = (tgt, line[1] if line else None, (line[2] + shift) if line else None)
    return out


for model, ids in (('X-H2S', (0x978, 0x2b9, 0x358)), ('X-T5', (0x9ff, 0x2b9, 0x358))):
    b = load(model, 'new', 0)
    r = find_core2(b)
    print(f'== {model} {b.version} b0 core={r[0]:#x} lim={r[1]:#x} tbl={r[2]:#x} anchor={r[3]:#x}' if r else f'== {model}: ядро не найдено')
    if r:
        for pid, v in decode(b, r[2], r[3], ids).items():
            print(f'   id {pid:#x}: case {v[0]:#x}  {v[1]}  -> settings+{(v[2] or 0):#x}')
