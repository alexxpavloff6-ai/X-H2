# -*- coding: utf-8 -*-
"""D2: кто ПИШЕТ blob[0xa8].

Сеттер u8 в блоке 0: X-H2 5.33 0x1492040 (`and w20,w1,#0xff; ldr x19,[blob];
bl 0x1491dd0; strb w20,[x19,w0]`). Ищем:
  1) все `strb w?, [x?, #0xa8]` в блоках 0/1/2 (прямая запись по смещению);
  2) все вызовы сеттера, перед которыми в w0 загружено 0xa8;
  3) для контроля — то же для чтения (get_u8), чтобы отличить.
"""
import sys, re, struct
sys.path.insert(0, r'<корень проекта>\Анализ_прошивки\Сравнение_версий_2026-11-16\D_брекетинг')
from dhelp import *  # noqa

# байтовый образец сеттера (new X-H2, 0x1492040) для поиска в других блоках/моделях
SETTER_PAT = bytes.fromhex('fd7bbea9fd030091f353bfa9f40300aa21004092'.replace(' ', ''))

def find_setter(model, state, idx):
    b = load(model, state, idx)
    hits = find_bytes(b, SETTER_PAT)
    return b, hits

for model in MODELS:
    for state in ('old', 'new'):
        for idx in (0, 1, 2):
            b, hits = find_setter(model, state, idx)
            if hits:
                print(f'{model} {state} b{idx}: сеттер(ы) u8 по образцу: {[hex(h) for h in hits][:4]}')

print('\n--- прямые записи strb по смещению 0xa8 ---')
for model in MODELS:
    for state in ('old', 'new'):
        for idx in (0, 1, 2):
            b = load(model, state, idx)
            ins = [x for x in all_insns(b) if x.mnemonic != '.byte']
            for x in ins:
                if x.mnemonic not in ('strb', 'str', 'strh'):
                    continue
                if not re.search(r'\[x\d+, #0xa8\]$', x.op_str):
                    continue
                ctx = [f'{y.mnemonic} {y.op_str}' for y in ins[max(0, ins.index(x) - 3):ins.index(x)]]
                print(f'{model} {state} b{idx}: {x.address:#x}: {x.mnemonic} {x.op_str}   <- {ctx}')
            break  # только блок 1 для скорости; для b0/b2 см. ниже
print('\n--- вызовы сеттера с id=0xa8 (блок 1, все модели) ---')
for model in MODELS:
    for state in ('old', 'new'):
        b = load(model, state, 1)
        d = b.data
        # цель сеттера: найдём по образцу в блоке 0 этой же модели/версии
        b0 = load(model, state, 0)
        sh = find_bytes(b0, SETTER_PAT)
        if not sh:
            print(f'{model} {state}: сеттер не найден в b0'); continue
        setter = sh[0]
        rows = []
        for o in range(0, len(d) - 3, 4):
            w = struct.unpack_from('<I', d, o)[0]
            if (w & 0x7c000000) != 0x14000000:
                continue
            imm = w & 0x3ffffff
            if imm & (1 << 25):
                imm -= 1 << 26
            if b.base + o + imm * 4 != setter:
                continue
            # ищем назад mov w0,#0xa8
            va = b.base + o
            ctx = insns(b, va - 0x24, 12)
            txt = [f'{y.mnemonic} {y.op_str}' for y in ctx]
            if any(t.startswith('mov w0, #0xa8') for t in txt):
                rows.append((va, txt))
        print(f'{model} {state}: setter={setter:#x}, вызовов с id 0xa8: {len(rows)}')
        for va, txt in rows[:10]:
            print(f'   {va:#x}: ' + ' | '.join(txt[-6:]))
