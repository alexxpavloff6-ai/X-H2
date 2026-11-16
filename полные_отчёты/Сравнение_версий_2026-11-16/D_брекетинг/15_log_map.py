# -*- coding: utf-8 -*-
"""D: карта отладочных сообщений функции подготовки кадра (X-H2 old/new, H2S, T5).

Вызовы лога: x1 = указатель на строку "[OFFSET] ..." (Shift-JIS), x0 = тег.
Скрипт находит все bl, перед которыми в x1 загружается указатель на такую
строку, и печатает адрес, строку и ближайшие инструкции (привязка к полю/свойству).
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

def raw_str(b, va, limit=200):
    o = b.off(va)
    if not 0 <= o < len(b.data):
        return None
    raw = b.data[o:o + limit].split(b'\x00')[0]
    return decode(raw) if raw else None

def find_offset_str(ins, i, b):
    for k in range(i - 1, max(-1, i - 16), -1):
        y = ins[k]
        if y.mnemonic != 'add' or not re.match(r'x\d+, x\d+, #', y.op_str):
            continue
        parts = [p.strip() for p in y.op_str.split(',')]
        reg, base, off = parts[0], parts[1], int(parts[2].split('#')[1], 0)
        for j in range(k - 1, max(-1, k - 8), -1):
            z = ins[j]
            if z.mnemonic == 'adrp' and z.op_str.startswith(base + ', '):
                page = int(z.op_str.split('#')[1], 0)
                s = raw_str(b, page + off)
                if s and s.startswith('[OFFSET]'):
                    return s, reg
    return None, None

CASES = [('X-H2', 'old', 0x2cecf2c, 0x2cedfc0),
         ('X-H2', 'new', 0x2ce8f3c, 0x2cea030)]
# H2S/T5 new: функция начинается до патча; найдём старт по func_start-эвристике
for m, pat in (('X-H2S', 0x3005378), ('X-T5', 0x2c2c5a0)):
    b = load(m, 'new', 1)
    s = func_start(b, pat)
    CASES.append((m, 'new', s, pat + 0x1000))

for model, tag, start, end in CASES:
    b = load(model, tag, 1)
    ins = [x for x in all_insns(b, start, end) if x.mnemonic != '.byte']
    rows = []
    for i, x in enumerate(ins):
        if x.mnemonic != 'bl':
            continue
        s, reg = find_offset_str(ins, i, b)
        if s and reg == 'x1':
            rows.append((x.address, s, ins[max(0, i - 3):i + 1]))
    print(f'\n===== {model} {tag} {start:#x}: {len(rows)} лог-вызовов [OFFSET]')
    for a, s, ctx in rows:
        print(f'--- {a:#x}: {s}')
        for c in ctx:
            print(f'      {c.address:#x}: {c.mnemonic} {c.op_str}')
