# -*- coding: utf-8 -*-
"""D2: кто ставит blob[0xa8] |= 0x80 и что это за операция.

Опорная последовательность (X-H2 5.33, 0x2fb0b64..0x2fb0be4):
  mov w0,#0xa8; bl get_u8; (tbnz w0,#7 -> выход); <проверки>; mov w19,w0;
  orr w1,w19,#0xffffff80; mov w0,#0xa8; bl set_u8; <работа>; mov w1,w19;
  mov w0,#0xa8; bl set_u8            <- восстановление исходного значения
Т.е. флаг ставится на время операции и затем возвращается.

Скрипт ищет `orr w1,w19,#0xffffff80` (и mov w19,w0) во всех моделях/версиях,
находит начало функции по индексу прологов, её вызывающих и строки функции.
"""
import sys, re, struct, json
sys.path.insert(0, r'<корень проекта>\Анализ_прошивки\Сравнение_версий_2026-11-16\D_брекетинг')
from dhelp import *  # noqa

model0 = 'X-H2'
b0 = load(model0, 'new', 1)
# слово `orr w1, w19, #0xffffff80` берём из эталона
o = b0.off(0x2fb0b90)
ORR = struct.unpack_from('<I', b0.data, o)[0]
o2 = b0.off(0x2fb0b8c)
MOV19 = struct.unpack_from('<I', b0.data, o2)[0]
print(f'эталон: mov w19,w0 = {MOV19:#010x}, orr w1,w19,#0xffffff80 = {ORR:#010x}')

def starts_index(b):
    out = []
    for o in range(0, len(b.data) - 3, 4):
        w = struct.unpack_from('<I', b.data, o)[0]
        if (w & 0xffc07fff) == 0xa9807bfd:
            out.append(b.base + o)
    return out

def decode(raw):
    for enc in ('shift_jis', 'cp932'):
        try:
            return raw.decode(enc)
        except Exception:
            pass
    return raw.decode('latin1')

def strings_of(b, lo, hi, limit=40):
    out = []
    ins = [x for x in all_insns(b, lo, hi) if x.mnemonic != '.byte']
    for i, x in enumerate(ins):
        if x.mnemonic != 'adrp':
            continue
        page = int(x.op_str.split('#')[1], 0)
        reg = x.op_str.split(',')[0]
        for y in ins[i + 1:i + 3]:
            if y.mnemonic == 'add' and y.op_str.startswith(reg + ', '):
                off = int(y.op_str.split('#')[1], 0)
                o2 = b.off(page + off)
                if 0 <= o2 < len(b.data):
                    raw = b.data[o2:o2 + 80].split(b'\x00')[0]
                    if raw and all(32 <= c < 127 for c in raw):
                        out.append(raw.decode('latin1'))
                break
    return out[:limit]

info = {}
for model in MODELS:
    for state in ('old', 'new'):
        b = load(model, state, 1)
        d = b.data
        hits = []
        for o in range(0, len(d) - 8, 4):
            if struct.unpack_from('<I', d, o)[0] != ORR:
                continue
            if struct.unpack_from('<I', d, o - 4)[0] != MOV19:
                continue
            hits.append(b.base + o - 4)
        starts = starts_index(b)
        callers = {}
        for o in range(0, len(d) - 3, 4):
            w = struct.unpack_from('<I', d, o)[0]
            if (w & 0x7c000000) != 0x14000000:
                continue
            imm = w & 0x3ffffff
            if imm & (1 << 25):
                imm -= 1 << 26
            tgt = b.base + o + imm * 4
            if b.base <= tgt < b.end:
                callers.setdefault(tgt, []).append(b.base + o)
        print(f'\n=== {model} {state}: писателей флага (set/restore) найдено {len(hits)}')
        for h in hits:
            fs = max([s for s in starts if s <= h], default=None)
            i = starts.index(fs) if fs in starts else None
            fs2 = starts[i + 1] if i is not None and i + 1 < len(starts) else b.end
            print(f'  {h:#x} (в функции {fs:#x})')
            ss = strings_of(b, fs, fs2)
            for s in ss[:10]:
                print(f'      "{s}"')
            cs = sorted(set(callers.get(fs, [])))
            print(f'      вызывающие: {[hex(c) for c in cs[:10]]}')
            info[f'{model} {state} {h:#x}'] = {'func': hex(fs), 'callers': [hex(c) for c in cs],
                                               'strings': ss}
json.dump(info, open('a8_flag_writer.json', 'w', encoding='utf8'), ensure_ascii=False, indent=1)
