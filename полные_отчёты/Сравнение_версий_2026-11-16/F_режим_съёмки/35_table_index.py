"""F: не служит ли [S+0]/[S+4]/[S+0xb4] индексом в таблицу (имена режимов)?

Ищем шаблон: ldr wN,[S+off]; ... ldr x?, [x?, wN, uxtw #2/#3]  (индексация таблицы
указателей/записей). Если найдётся — таблица даст имена значений.
"""
import sys, re, struct, collections
sys.path.insert(0, '<корень проекта>/Анализ_прошивки/Сравнение_версий_2026-11-16/F_режим_съёмки')
from fhelp import *

S, PAGE = 0x244eb20, 0x244e000
FIELDS = {0x0: 'S+0', 0x4: 'S+4', 0xb0: 'S+0xb0', 0xb4: 'S+0xb4'}


def reg(t):
    m = re.fullmatch(r'[xw](\d+)', t.strip())
    return f'x{m.group(1)}' if m else None


for idx in (0, 1):
    b = load('X-H2', 'new', idx)
    hits = []
    for va, r0 in adrp_sites(b, PAGE):
        r = f'x{r0}'
        for x in insns(b, va + 4, 3):
            m = re.fullmatch(r'(x\d+), (x\d+), #(-?0x[0-9a-f]+|-?\d+)', x.op_str)
            if x.mnemonic == 'add' and m and m.group(2) == r and int(m.group(3), 0) == 0xb20:
                base = reg(m.group(1))
                for y in insns(b, x.address + 4, 30):
                    mm = re.fullmatch(r'\w+, \[x\d+(?:, #-?(?:0x[0-9a-f]+|\d+))?\]', y.op_str)
                    if mm and y.mnemonic.startswith('ldr'):
                        offm = re.search(r'#(-?0x[0-9a-f]+|-?\d+)\]', y.op_str)
                        off = int(offm.group(1), 0) if offm else 0
                        if off not in FIELDS:
                            continue
                        dst = reg(y.op_str.split(',')[0])
                        blob = ' ; '.join(f'{z.mnemonic} {z.op_str}'
                                          for z in insns(b, y.address + 4, 10))
                        if re.search(rf'\[x\d+, {dst}, uxtw #\d\]', blob) or \
                           re.search(rf'\[x\d+, {dst}\]', blob):
                            hits.append((y.address, FIELDS[off], blob))
                    if y.mnemonic in ('bl', 'ret', 'b'):
                        break
                break
            if x.mnemonic in ('bl', 'b', 'ret', 'br'):
                break
    print(f'== b{idx}: индексаций таблиц по полям S: {len(hits)}')
    for a, f, blob in hits[:20]:
        print(f'  {a:x} {f}: {blob}')
