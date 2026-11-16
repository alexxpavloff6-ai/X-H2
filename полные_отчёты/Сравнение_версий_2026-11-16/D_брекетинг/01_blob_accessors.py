# -*- coding: utf-8 -*-
"""D: кто такой property_getter (0x1492110) и где база кэшированного blob.

Запуск: python 01_blob_accessors.py
Печатает: дизассемблер аксессоров, всех писателей/читателей глобала базы blob,
и все места, где встречается константа 0x19155 (в 3 моделях, old/new).
"""
import sys, json, struct
sys.path.insert(0, r'<корень проекта>\Анализ_прошивки\Сравнение_версий_2026-11-16')
from fwcommon import *  # noqa

OUT = {}

def show(title, text):
    print('=' * 70)
    print(title)
    print('=' * 70)
    print(text)

# --- 1. аксессоры в блоке 0 X-H2 new ---
b0 = load('X-H2', 'new', 0)
show('X-H2 new b0 0x1491dd0 (bounds) / 0x1491e5c (byte accessor)', dis(b0, 0x1491dd0, 30))
show('X-H2 new b0 0x14920fc..0x14921d0 (типизированные геттеры)', dis(b0, 0x14920fc, 56))

# --- 2. ссылки на глобал базы blob 0x20bf458 ---
print('=' * 70)
print('Ссылки на 0x20bf458 (база blob) по всем моделям/блокам')
print('=' * 70)
refs_all = {}
for m in MODELS:
    for st in ('old', 'new'):
        for idx in (0, 1, 2):
            b = load(m, st, idx)
            refs = adrp_refs(b, 0x20bf458, window=10)
            if refs:
                refs_all[f'{m} {st} b{idx}'] = [r['insn'] for r in refs]
                print(f'--- {m} {st} b{idx}')
                for r in refs:
                    print('   ', r['insn'])
print(json.dumps(refs_all, ensure_ascii=False, indent=1))

# --- 3. константа 0x19155: mov/movk пары и сама по себе ---
print('=' * 70)
print('Вхождения константы 0x19155 (mov w0,#0x9155; movk w0,#1,lsl#16)')
print('=' * 70)
def find_const(b, value, limit=4000):
    """movz/movk последовательности, дающие value, и просто imm16==low."""
    hits = []
    data, base = b.data, b.base
    n = len(data)
    for o in range(0, n - 3, 4):
        w = struct.unpack_from('<I', data, o)[0]
        # movz: 0x52800000 mask ; movk: 0x72800000
        if (w & 0x7f800000) in (0x52800000, 0x72800000):
            hw = (w >> 21) & 3
            imm = (w >> 5) & 0xffff
            rd = w & 31
            val = imm << (16 * hw)
            if val == value:
                hits.append((base + o, f'movz/movk x{rd} #{imm:#x} lsl{16*hw}'))
    return hits

for m in MODELS:
    for st in ('old', 'new'):
        for idx in (0, 1, 2):
            b = load(m, st, idx)
            hits = find_const(b, 0x19155)
            if hits:
                print(f'{m} {st} b{idx}: {len(hits)} movz/movk imm16=0x9155')
                for va, s in hits[:20]:
                    print(f'   {va:#x} {s}')

# --- 4. сколько всего обращений к property_getter 0x1492110 / 0x14920fc в блоке 1 ---
b1 = load('X-H2', 'new', 1)
c1 = bl_callers(b1, 0x1492110)
c2 = bl_callers(b1, 0x14920fc)
print(f'X-H2 new b1: bl 0x1492110 = {len(c1)}, bl 0x14920fc = {len(c2)}')
