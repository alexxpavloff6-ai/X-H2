# -*- coding: utf-8 -*-
"""D2: точный поиск писателей blob[0xa8].

1) Образец сеттера u8 берём прямо из блока 0 по известному адресу (X-H2 5.33 0x1492040).
2) Все вызовы сеттера в блоках 0 и 1; смотрим назад и определяем id (w0) и значение (w1).
3) `strb w?, [xN, #0xa8]`, где xN загружен из глобала blob — прямая запись без сеттера.
Потоковый обход блоков (без хранения всех инструкций).
"""
import sys, re, struct
from collections import deque
sys.path.insert(0, r'<корень проекта>\Анализ_прошивки\Сравнение_версий_2026-11-16\D_брекетинг')
from dhelp import *  # noqa

b0 = load('X-H2', 'new', 0)
PAT = b0.data[b0.off(0x1492040):b0.off(0x1492040) + 0x2c]
print('образец сеттера:', PAT.hex())

BLOB_GLOBAL = {('X-H2', 'old'): 0x20c1458, ('X-H2', 'new'): 0x20bf458,
               ('X-H2S', 'old'): 0x23dbc30, ('X-H2S', 'new'): 0x23dbc30,
               ('X-T5', 'old'): 0x2066d90, ('X-T5', 'new'): 0x2066d90}

for model in MODELS:
    for state in ('old', 'new'):
        b0, b1 = load(model, state, 0), load(model, state, 1)
        setters = set(find_bytes(b0, PAT))
        print(f'\n=== {model} {state}: сеттеры в b0: {[hex(x) for x in setters]}')
        if not setters:
            continue
        gpage = BLOB_GLOBAL[(model, state)] & ~0xfff
        call_hits, direct_hits = [], []
        for blk in (b0, b1):
            hist = deque(maxlen=14)
            for x in all_insns(blk):
                if x.mnemonic == '.byte':
                    continue
                # прямые записи через базу blob
                if x.mnemonic in ('strb', 'str'):
                    m = re.search(r'\[(x\d+), #0xa8\]$', x.op_str)
                    if m:
                        reg = m.group(1)
                        page = None
                        for y in hist:
                            if y.mnemonic == 'adrp':
                                page = int(y.op_str.split('#')[1], 0)
                            if (y.mnemonic == 'ldr' and re.search(r'\[x\d+, #0x458\]', y.op_str)
                                    and y.op_str.startswith(reg + ',') and page == gpage):
                                direct_hits.append((x.address, f'{x.mnemonic} {x.op_str}'))
                # вызовы сеттера
                if x.mnemonic in ('bl', 'b'):
                    try:
                        tgt = int(x.op_str.split('#')[1], 0)
                    except Exception:
                        tgt = None
                    if tgt in setters:
                        idv = valv = None
                        for y in reversed(list(hist)):
                            t = f'{y.mnemonic} {y.op_str}'
                            if idv is None and t.startswith('mov w0, #'):
                                idv = int(t.split('#')[1], 0)
                            if valv is None and t.startswith('mov w1, #'):
                                valv = int(t.split('#')[1], 0)
                            if y.mnemonic in ('bl', 'b'):
                                break
                        if idv == 0xa8:
                            call_hits.append((x.address, x.mnemonic, valv,
                                              [f'{y.mnemonic} {y.op_str}' for y in list(hist)[-6:]]))
                hist.append(x)
        print(f'  вызовов сеттера с id=0xa8: {len(call_hits)}')
        for va, kind, valv, txt in call_hits[:20]:
            print(f'    {va:#x} {kind} value={None if valv is None else hex(valv)}: ' + ' | '.join(txt))
        print(f'  прямых записей через базу blob: {len(direct_hits)}')
        for a, s in direct_hits[:10]:
            print(f'    {a:#x}: {s}')
