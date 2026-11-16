"""F: кросс-модельный поиск проверок режима (потоковый, без гигантских списков).

Идиомы:
  sub wN,wN,#0xd ; cmp wN,#5      -> значение в 0xd..0x12
  sub wN,wN,#0xb ; cmp wN,#1      (+ccmp #0xe)  -> 0xb,0xc,0xe...
  and wN,wN,#~2  ; cmp wN,#0xc    -> 0xc/0xe
  cmp wN,#8 в паре с предыдущим ldr из S
"""
import sys, re, json, struct, collections
sys.path.insert(0, '<корень проекта>/Анализ_прошивки/Сравнение_версий_2026-11-16/F_режим_съёмки')
from fhelp import *
import fwcommon

BLOCK = 1 << 16


def stream(b):
    base, data = b.base, b.data
    for o in range(0, len(data) - 3, BLOCK):
        chunk = data[o:o + BLOCK + 16]
        for ins in cs.disasm(chunk, base + o):
            if ins.address >= base + len(data):
                break
            yield ins


def next_insn(b, va):
    xs = insns(b, va, 1)
    return xs[0] if xs else None


for model in MODELS:
    for state in ('old', 'new'):
        b = load(model, state, 1)
        hits = []
        for x in stream(b):
            s = x.op_str
            if x.mnemonic == 'sub':
                m = re.fullmatch(r'(w\d+), w\d+, #(0xd|0xb|0x2)', s)
                if not m:
                    continue
                reg, imm = m.group(1), int(m.group(2), 16)
                n = next_insn(b, x.address + 4)
                if n and n.mnemonic == 'cmp':
                    m2 = re.fullmatch(rf'{reg}, #(0x[0-9a-f]+|\d+)', n.op_str)
                    if m2 and ((imm, int(m2.group(1), 0)) in ((0xd, 5), (0xb, 1), (0x2, 1))):
                        hits.append((x.address, f'sub #{imm:#x}; cmp #{int(m2.group(1),0):#x}'))
            elif x.mnemonic == 'and' and '#0xfffffffd' in s:
                m = re.fullmatch(r'(w\d+), w\d+, #0xfffffffd', s)
                if not m:
                    continue
                n = next_insn(b, x.address + 4)
                if n and n.mnemonic == 'cmp' and n.op_str == f'{m.group(1)}, #0xc':
                    hits.append((x.address, 'and ~2; cmp #0xc'))
        print(f'== {model} {b.version} b1: {len(hits)}')
        for a, what in hits[:20]:
            pre = dis(b, a - 20, 6).replace('\n', ' ; ')
            print(f'   {a:x}: {what}  <= {pre}')
