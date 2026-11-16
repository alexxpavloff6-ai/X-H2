# -*- coding: utf-8 -*-
"""E26: сеттер байтового blob-настроек 0x1492040(id, value).
Собираем все вызовы, восстанавливаем (id,value) из mov/movk и ищем id 0x2801C
и/или value 0x2C. Также ищем саму константу 0x2801C (mov w0,#0x801c; movk w0,#2)."""
import sys, re, struct
sys.path.insert(0, r'<корень проекта>\Анализ_прошивки\Сравнение_версий_2026-11-16\E_сеттер_0x2B9')
from ecommon import *  # noqa

TGT_ID = 0x2801c
for model in ('X-H2',):
    for state in ('new',):
        for idx in (0, 1):
            b = load(model, state, idx)
            print(f'\n######## {model} {state} блок {idx} {b} ########')
            # 1) константа 0x2801c как movz+movk
            pat_movz = struct.pack('<I', 0x52800000 | ((TGT_ID & 0xffff) << 5) | 0)          # movz w0,#0x801c
            pat_movk = struct.pack('<I', 0x72a00000 | ((TGT_ID >> 16) << 5) | 0)            # movk w0,#2
            h1 = find_bytes(b, pat_movz)
            print(f'  movz w0,#0x801c: {[hex(x) for x in h1][:10]}')
            for x in h1:
                nxt = list(insns(b, x + 4, 2))
                print(f'    {x:#x} -> {[f"{y.mnemonic} {y.op_str}" for y in nxt]}')

            # 2) все вызовы сеттера 0x1492040
            sites = [a for a, k in bl_callers(b, 0x1492040) if k == 'bl']
            print(f'  вызовов 0x1492040: {len(sites)}')
            interesting = []
            for a in sites:
                hist = [x for x in all_insns(b, a - 0x28, a) if x.mnemonic != '.byte']
                # восстановим w0 и w1
                def reg_val(reg):
                    val = None
                    for y in reversed(hist):
                        if y.mnemonic in ('mov', 'movz') and re.match(reg + r', #', y.op_str):
                            return int(y.op_str.split('#')[1], 0)
                        if y.mnemonic == 'movk' and re.match(reg + r', #', y.op_str):
                            imm = int(y.op_str.split('#')[1].split(',')[0], 0)
                            sh = y.op_str.rsplit('lsl #', 1)
                            sh = int(sh[1]) if len(sh) > 1 else 0
                            return val + (imm << sh) if val is not None else None
                        if y.mnemonic == 'mov' and re.match(reg + r', w', y.op_str):
                            return None
                    return None
                idv, valv = reg_val('w0'), reg_val('w1')
                if (idv is not None and 0x27f00 <= idv <= 0x28100) or (valv is not None and valv == 0x2c):
                    interesting.append((a, idv, valv, hist))
            print(f'  интересных (id 0x28xxx или value 0x2c): {len(interesting)}')
            for a, idv, valv, hist in interesting:
                print(f'   --- {a:#x}  id={idv if idv is None else hex(idv)} value={valv if valv is None else hex(valv)}')
                for y in hist[-8:]:
                    print(f'       {y.address:x}: {y.mnemonic:8} {y.op_str}')
