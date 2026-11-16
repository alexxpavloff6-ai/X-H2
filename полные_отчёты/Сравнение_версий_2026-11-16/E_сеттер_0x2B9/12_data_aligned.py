# -*- coding: utf-8 -*-
"""E12: только реальные данные (выровненное слово, не декодированное как инструкция).
Ищем u16 0x2b9 в данных блоков 0/1 и смотрим окно u16/u32."""
import sys, re, struct, json
sys.path.insert(0, r'<корень проекта>\Анализ_прошивки\Сравнение_версий_2026-11-16\E_сеттер_0x2B9')
from ecommon import *  # noqa
from pathlib import Path

HERE = Path(__file__).resolve().parent
MODEL, STATE = 'X-H2', 'new'


def code_map(idx):
    p = HERE / f'code_map_{idx}.json'
    d = json.loads(p.read_text())
    return set(d['insn'])


for idx in (0, 1):
    b = load(MODEL, STATE, idx)
    cov = code_map(idx)
    print(f'\n######## блок {idx} ########')
    for width in (2, 4):
        pat = struct.pack('<H' if width == 2 else '<I', 0x2b9)
        hits = []
        start = 0
        while True:
            i = b.data.find(pat, start)
            if i < 0:
                break
            a = b.base + i
            if a % 4 == 0 and a not in cov:
                hits.append(a)
            start = i + 1
        print(f'\nu{width*8} 0x2b9 в реальных данных: {len(hits)}')
        for a in hits:
            o = b.off(a)
            u16s = [struct.unpack_from('<H', b.data, o + 2 * k)[0] for k in range(14)]
            flag = ' <== 0x2c!'
            print(f'  {a:#x}: u16 {[hex(v) for v in u16s]}' + (flag if 0x2c in u16s else ''))
