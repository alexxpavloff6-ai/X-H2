# -*- coding: utf-8 -*-
"""E30: финальные проверки.
1) Есть ли где-либо константа 0x2801C (movz wN,#0x801c + movk wN,#2) в любом регистре.
2) Кросс-модельная проверка: в блоке 1 X-H2S 7.31 / X-T5 4.32 есть ли та же связка
   «база 0x28000 + 0x13 -> strb [xN,#0x144]» (то есть [ctx+0x3978] из blob-настроек),
   и тот же ли сток в 0x30871ac (ldr w1,[x19,#0x144]; str w1,[x0,#0x3978]).
"""
import sys, re, struct
sys.path.insert(0, r'<корень проекта>\Анализ_прошивки\Сравнение_версий_2026-11-16\E_сеттер_0x2B9')
from ecommon import *  # noqa

print('=== 1) константа 0x2801C в коде (любой регистр) ===')
for idx in (0, 1):
    b = load('X-H2', 'new', idx)
    print(f'-- блок {idx}')
    found = 0
    words = {}
    for va, w in iter_words(b):
        words[va] = w
    for va, w in words.items():
        # movz wN,#0x801c  (sf=0, opc=10, hw=00): 0x52800000 | imm16<<5 | Rd
        if (w & 0xffe0001f) == (0x52800000 | (0x801c << 5)):
            reg = w & 31
            nxt = words.get(va + 4, 0)
            if (nxt & 0xffe0001f) == (0x72a00000 | (2 << 5) | reg):
                print(f'   {va:#x}: movz w{reg},#0x801c ; movk w{reg},#2')
                found += 1
    print('   найдено:', found)

print('\n=== 2) кросс-модельная проверка ===')
for model, states in (('X-H2', ('new',)), ('X-H2S', ('new',)), ('X-T5', ('new',))):
    for state in states:
        try:
            b1 = load(model, state, 1)
        except Exception as e:
            print(model, state, 'ошибка', e)
            continue
        print(f'\n-- {model} {b1.version} блок 1 base={b1.base:#x}')
        # ищем пары: str w1,[xN,#0x3978] и предшествующий ldr w1,[xM,#0x144]
        hits = []
        for x in all_insns(b1):
            if x.mnemonic == '.byte':
                continue
            if x.mnemonic == 'str' and re.search(r'\[x\d+, #0x3978\]', x.op_str):
                prev = [y for y in all_insns(b1, max(b1.base, x.address - 8), x.address) if y.mnemonic != '.byte']
                hits.append((x.address, prev))
        print('   записей [*, #0x3978]:', len(hits))
        for a, prev in hits[:6]:
            print(f'   {a:#x}: ' + ' | '.join(f'{p.address:x}:{p.mnemonic} {p.op_str}' for p in prev[-2:]))
        # ищем fill: add w0,w19,#0x28,lsl#12 + add #0x13 + bl + strb [xN,#0x144]
        for x in all_insns(b1):
            if x.mnemonic == '.byte':
                continue
            if x.mnemonic == 'add' and re.match(r'w\d+, w\d+, #0x28, lsl #12$', x.op_str):
                seq = [y for y in all_insns(b1, x.address, x.address + 0x18) if y.mnemonic != '.byte']
                txt = ' | '.join(f'{y.mnemonic} {y.op_str}' for y in seq)
                if '#0x13' in txt and '#0x144' in txt:
                    print(f'   fill-связка {x.address:#x}: {txt}')
                    break
