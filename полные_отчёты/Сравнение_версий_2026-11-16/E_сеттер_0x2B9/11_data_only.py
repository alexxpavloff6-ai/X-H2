# -*- coding: utf-8 -*-
"""E11: карта «код/данные» для блоков 0/1 X-H2 5.33 (кэш в code_map_*.json),
и поиск u16 0x2b9 ТОЛЬКО в данных + окно значений.
"""
import sys, re, struct, json
sys.path.insert(0, r'<корень проекта>\Анализ_прошивки\Сравнение_версий_2026-11-16\E_сеттер_0x2B9')
from ecommon import *  # noqa
from pathlib import Path

HERE = Path(__file__).resolve().parent
MODEL, STATE = 'X-H2', 'new'


def code_map(idx):
    p = HERE / f'code_map_{idx}.json'
    if p.exists():
        d = json.loads(p.read_text())
        return set(d['insn'])
    b = load(MODEL, STATE, idx)
    s = set()
    for x in all_insns(b):
        if x.mnemonic != '.byte':
            s.add(x.address)
    p.write_text(json.dumps({'insn': sorted(s)}))
    return s


for idx in (0, 1):
    b = load(MODEL, STATE, idx)
    cov = code_map(idx)
    print(f'\n######## блок {idx}: инструкций {len(cov)} ########')
    pat = struct.pack('<H', 0x2b9)
    hits = []
    start = 0
    while True:
        i = b.data.find(pat, start)
        if i < 0:
            break
        a = b.base + i
        if a not in cov:      # не начало инструкции => данные
            hits.append(a)
        start = i + 1
    print(f'u16 0x2b9 в данных: {len(hits)}')
    for a in hits:
        o = b.off(a)
        win = b.data[max(0, o - 16):o + 32]
        u16s = [struct.unpack_from('<H', b.data, o + 2 * k)[0] for k in range(12)] if o + 24 < len(b.data) else []
        flag = ' <== 0x2c!' if 0x2c in u16s else ''
        print(f'  {a:#x}: {win.hex(" ")}  u16: {[hex(v) for v in u16s]}{flag}')
