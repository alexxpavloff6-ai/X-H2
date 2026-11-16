"""F2: функции, пишущие несколько «полей job» (+0x12c, +0x130, +0x144, +0x148, +0x150).

RECF-копия читает job+0x12c, +0x130, +0x144 (X-H2 5.33). Ищем функции, где есть
записи хотя бы в два из этих смещений — это «строители задания».
"""
import sys, re, struct, collections
sys.path.insert(0, '<корень проекта>/Анализ_прошивки/Сравнение_версий_2026-11-16/F_режим_съёмки')
from fhelp import *

FIELDS = {0x12c, 0x130, 0x144, 0x148, 0x150, 0x140}
b = load('X-H2', 'new', 1)

per_func = collections.defaultdict(list)
for va, w in iter_words(b):
    ins = insns(b, va, 1)
    if not ins:
        continue
    x = ins[0]
    if not x.mnemonic.startswith('st'):
        continue
    for off in FIELDS:
        if re.fullmatch(rf'\w+, \[x\d+, #{off:#x}\]', x.op_str):
            fs, fe = func_range(b, va, 0x6000)
            per_func[fs].append((va, off, f'{x.mnemonic} {x.op_str}'))
            break

rows = [(fs, v) for fs, v in per_func.items() if len({o for _, o, _ in v}) >= 2]
rows.sort(key=lambda kv: -len(kv[1]))
print(f'функций с ≥2 полями job: {len(rows)}')
for fs, v in rows[:25]:
    offs = sorted({o for _, o, _ in v})
    print(f'  func {fs:#x}: offsets {[hex(o) for o in offs]}')
    for va, o, ins in v[:8]:
        print(f'      {va:x}: {ins}')
