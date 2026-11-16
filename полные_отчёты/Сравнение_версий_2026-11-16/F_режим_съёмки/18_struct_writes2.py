"""F: писатели S = 0x244eb20 (0x2940 байт) с трассировкой mov/orr/add цепочек.

Прошлый скан не учитывал `mov x19, x0` (копирование базы) — из-за этого писатели
могли быть пропущены. Здесь отслеживаем: add (reg+imm), mov (reg), adrp (страница),
на всём протяжении функции (до ret/prologue), плюс чтения/записи по [reg,#off].
"""
import sys, re, json, struct, collections
sys.path.insert(0, '<корень проекта>/Анализ_прошивки/Сравнение_версий_2026-11-16/F_режим_съёмки')
from fhelp import *

S, SZ, PAGE = 0x244eb20, 0x2940, 0x244e000


def walk(b, count):
    """Один проход по инструкциям с отслеживанием регистров-указателей."""
    tracked = {}
    events = []
    for x in insns(b, b.base, 0):
        pass
    return events


def scan_func(b, fs, fe):
    tracked = {}
    out = []
    for x in insns(b, fs, max(1, (fe - fs) // 4)):
        ops = [p.strip() for p in x.op_str.split(',')]
        if x.mnemonic == 'adrp':
            m = re.fullmatch(r'(x\d+), #(0x[0-9a-f]+|-?\d+)', x.op_str)
            if m:
                tracked[m.group(1)] = int(m.group(2), 0)
        elif x.mnemonic == 'add' and len(ops) == 3:
            m = re.fullmatch(r'(x\d+), (x\d+), #(-?0x[0-9a-f]+|-?\d+)', x.op_str)
            if m and m.group(2) in tracked:
                tracked[m.group(1)] = tracked[m.group(2)] + int(m.group(3), 0)
                continue
        elif x.mnemonic in ('mov', 'orr') and len(ops) == 2 and ops[1] in tracked:
            tracked[ops[0]] = tracked[ops[1]]
        elif x.mnemonic == 'mov' and len(ops) == 3 and ops[1] in tracked and ops[2] == '#0':
            tracked[ops[0]] = tracked[ops[1]]
        mem = re.search(r'\[(x\d+)(?:,\s*#(-?0x[0-9a-f]+|-?\d+))?\]', x.op_str)
        if mem and mem.group(1) in tracked:
            off = int(mem.group(2), 0) if mem.group(2) else 0
            tgt = tracked[mem.group(1)] + off
            if S <= tgt < S + SZ:
                out.append(dict(site=x.address, insn=f'{x.mnemonic} {x.op_str}',
                                addr=tgt, field=tgt - S,
                                write=x.mnemonic.startswith('st')))
        if x.mnemonic in ('ldr', 'ldrb', 'ldrh', 'ldrsw', 'ldrsb', 'ldrsh') and ops and ops[0] in tracked:
            # загрузка в регистр, который был указателем — сбрасываем
            if ops[0] in tracked:
                del tracked[ops[0]]
    return out


b0 = load('X-H2', 'new', 0)
b1 = load('X-H2', 'new', 1)
sites = []
for b in (b0, b1):
    for va, reg in adrp_sites(b, PAGE):
        r = f'x{reg}'
        for x in insns(b, va + 4, 4):
            m = re.fullmatch(r'(x\d+), (x\d+), #(-?0x[0-9a-f]+|-?\d+)', x.op_str)
            if x.mnemonic == 'add' and m and int(m.group(3), 0) in (0xb20, 0xb4c):
                sites.append((b, x.address))
                break
            if x.mnemonic in ('bl', 'ret', 'br', 'b'):
                break

found = collections.Counter()
writes = []
for b, s in sites:
    fs, fe = func_range(b, s)
    for e in scan_func(b, fs, fe):
        if e['write']:
            writes.append((b, e))
            found[e['field']] += 1
print('всего сайтов-баз:', len(sites))
print('найдено записей:', len(writes))
for f, n in sorted(found.items()):
    print(f'  поле S+{f:#05x}: {n}')
for b, e in writes:
    print(f"  {e['site']:x}: {e['insn']}  -> S+{e['field']:#x}")
json.dump([{k: (hex(v) if isinstance(v, int) else v) for k, v in e.items()} | {'block': e and b.idx}
           for b, e in writes], open('struct_writes2.json', 'w'), indent=1)
