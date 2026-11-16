# -*- coding: utf-8 -*-
"""D: сопоставление полей params (x19) с отладочными именами.

В функции подготовки кадра отладочный вывод сделан out-of-line заглушками:
  ldrsh w2, [x19, #off]      ; значение поля
  adrp x1,<строка [OFFSET]>
  add  x1, x1, #...
  bl   <log>
То есть имя из строки относится именно к полю params+off. Скрипт собирает такое
соответствие для трёх моделей и печатает таблицу off -> имя. Дополнительно ищет
имена для полей commit (x22) и значения +0x60/+0x80.
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

def raw_str(b, va, limit=160):
    o = b.off(va)
    if not 0 <= o < len(b.data):
        return None
    raw = b.data[o:o + limit].split(b'\x00')[0]
    return decode(raw) if raw else None

def strings_map(model, tag, start, end):
    b = load(model, tag, 1)
    ins = [x for x in all_insns(b, start, end) if x.mnemonic != '.byte']
    # индекс: adrp reg -> page
    res = []       # (адрес загрузки значения, выражение, адрес bl, строка)
    for i, x in enumerate(ins):
        if x.mnemonic != 'bl':
            continue
        # назад: найти adrp/add "[OFFSET]" (x1) и перед ним загрузку w2/w3
        s = None
        for k in range(i - 1, max(-1, i - 8), -1):
            y = ins[k]
            if y.mnemonic == 'add' and y.op_str.startswith('x1, x1, #'):
                off = int(y.op_str.split('#')[1], 0)
                for j in range(k - 1, max(-1, k - 4), -1):
                    z = ins[j]
                    if z.mnemonic == 'adrp' and z.op_str.startswith('x1, '):
                        s = raw_str(b, int(z.op_str.split('#')[1], 0) + off)
                        break
                break
        if not (s and s.startswith('[OFFSET]')):
            continue
        # ищем загрузку значения-аргумента в w2/w3 непосредственно перед adrp x1
        val = None
        for k in range(i - 1, max(-1, i - 12), -1):
            y = ins[k]
            m = re.match(r'w([23]), \[(x\d+)(?:, #(0x[0-9a-f]+))?\]$', y.op_str)
            if y.mnemonic in ('ldrsh', 'ldrh', 'ldr', 'ldrb', 'sxtb', 'sxth') and m:
                base = m.group(2)
                off = int(m.group(3), 0) if m.group(3) else 0
                val = f'{y.mnemonic} w{m.group(1)}, [{base}, #{off:#x}]'
                break
            if y.mnemonic == 'mov' and y.op_str.startswith('w2, w'):
                val = y.op_str
                break
        res.append((x.address, val, s))
    return res

CASES = [('X-H2', 'old', 0x2cecf2c, 0x2cedfc0),
         ('X-H2', 'new', 0x2ce8f3c, 0x2cea030)]
for m, pat in (('X-H2S', 0x3005378), ('X-T5', 0x2c2c5a0)):
    b = load(m, 'new', 1)
    CASES.append((m, 'new', func_start(b, pat), pat + 0x1200))

for model, tag, start, end in CASES:
    rows = strings_map(model, tag, start, end)
    print(f'\n===== {model} {tag} ({start:#x}..{end:#x}): {len(rows)} именованных логов')
    for a, val, s in rows:
        print(f'  bl {a:#x}  arg={val!s:<34} {s}')
