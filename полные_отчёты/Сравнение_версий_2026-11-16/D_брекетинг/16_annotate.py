# -*- coding: utf-8 -*-
"""D: дизассемблер с подстановкой строк: рядом с adrp+add, дающими ASCII/[OFFSET]
строку, печатается её текст (Shift-JIS декодируется). Помогает читать участки
функции подготовки кадра, где считаются именованные параметры.
"""
import sys, re
sys.path.insert(0, r'<корень проекта>\Анализ_прошивки\Сравнение_версий_2026-11-16\D_брекетинг')
from dhelp import *  # noqa

def decode(raw):
    for enc in ('shift_jis', 'cp932'):
        try:
            return raw.decode(enc)
        except Exception:
            pass
    return raw.decode('latin1')

def raw_str(b, va, limit=120):
    o = b.off(va)
    if not 0 <= o < len(b.data):
        return None
    raw = b.data[o:o + limit].split(b'\x00')[0]
    if not raw:
        return None
    try:
        s = decode(raw)
    except Exception:
        return None
    if all(32 <= ord(c) < 127 or ord(c) > 0x2000 for c in s) and len(s) >= 3:
        return s
    return None

def annotate(model, tag, lo, hi):
    b = load(model, tag, 1)
    ins = [x for x in all_insns(b, lo, hi) if x.mnemonic != '.byte']
    pend = {}
    for x in ins:
        note = ''
        if x.mnemonic == 'adrp' and re.match(r'x\d+, #', x.op_str):
            reg = x.op_str.split(',')[0]
            pend[reg] = int(x.op_str.split('#')[1], 0)
            note = ''
        elif x.mnemonic == 'add' and re.match(r'x\d+, x\d+, #', x.op_str):
            parts = [p.strip() for p in x.op_str.split(',')]
            reg, base, off = parts[0], parts[1], int(parts[2].split('#')[1], 0)
            if base in pend:
                s = raw_str(b, pend[base] + off)
                if s:
                    note = '   ; "' + s + '"'
        print(f'{x.address:#010x}: {x.mnemonic:8} {x.op_str}{note}')

if __name__ == '__main__':
    annotate('X-H2', 'new', 0x2ce98d0, 0x2ce9b40)
