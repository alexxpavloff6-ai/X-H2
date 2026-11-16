"""53: писатели флага в деталях: откуда берётся значение w2, кто заполняет pending, и то же для 5.30.

* 5.33: дизасм функций-писателей 0x3104660..0x3104740 и 0x3104bb0..0x3104c60 (str w2,[x0,#0x43c]);
* 5.33: дизасм 0x31014e0..0x3101570 (кто кладёт данные в pending 0x4C3B090 / current 0x4C3B1F8);
* 5.30: трекер с адресами +0x4000 (pending 0x4C3F090, current 0x4C3F1F8, state 0x4C33EA0,
  флаг 0x4C33F14), чтобы подтвердить сдвиг данных.

Только чтение.
"""
import json
import re
import sys
from pathlib import Path

import numpy as np

HERE = Path(__file__).resolve().parent
sys.path.insert(0, str(HERE))
import m4lib

sys.path.insert(0, str(m4lib.ANALYSIS / 'Сравнение_версий_2026-11-16'))
import fwcommon

lines = []
out = {}


def emit(s=''):
    print(s)
    lines.append(s)


def win(b, lo, hi, tag=''):
    emit(f'--- {tag} [{lo:#x}..{hi:#x})')
    for x in fwcommon.insns(b, lo, (hi - lo) // 4):
        emit(f'  {x.address:08x}  {x.bytes.hex():<10} {x.mnemonic:<8} {x.op_str}')


b = fwcommon.load('X-H2', 'new', 1)
win(b, 0x3104660, 0x3104740, '5.33 писатель №1 (str w2,[x0,#0x43c])')
win(b, 0x3104BB0, 0x3104C60, '5.33 писатель №2')
win(b, 0x31014E0, 0x3101560, '5.33 заполнение pending/current')

# --------------------------------------------------------------- 5.30: сдвиг +0x4000
emit('\n== 5.30: трекер по адресам +0x4000')
b30 = fwcommon.load('X-H2', 'old', 1)
RANGES = {'pending_5.30': (0x4C3F090, 0x4C3F1F8), 'current_5.30': (0x4C3F1F8, 0x4C3F360),
          'state_5.30': (0x4C33EA0, 0x4C34000), 'flag_5.30': (0x4C33F14, 0x4C33F18)}
TGT = 0x4C33F14
a = np.frombuffer(b30.data[:len(b30.data) & ~3], dtype='<u4').astype(np.uint64)
idx = np.nonzero((a & 0x9F000000) == 0x90000000)[0]
hits = []
for i in idx:
    site = b30.base + int(i) * 4
    seq = fwcommon.insns(b30, site, 3)
    if len(seq) < 2 or seq[1].mnemonic not in ('add', 'adds'):
        continue
    m1 = re.search(r'#(0x[0-9a-f]+)', seq[0].op_str)
    m2 = re.search(r'#(0x[0-9a-f]+)', seq[1].op_str)
    if not (m1 and m2):
        continue
    ops = [p.strip() for p in seq[1].op_str.split(',')]
    if len(ops) < 2 or ops[0] != ops[1]:
        continue
    base = int(m1.group(1), 0) + int(m2.group(1), 0)
    reg = ops[0]
    for x in fwcommon.insns(b30, seq[1].address + 4, 60):
        dst = x.op_str.split(',')[0].strip() if x.op_str else ''
        if x.mnemonic.startswith(('str', 'stp')):
            mm = re.search(r'\[(x\d+|w\d+|sp)(?:, #(0x[0-9a-f]+|\d+))?\]', x.op_str)
            if mm and mm.group(1) == reg:
                imm = int(mm.group(2), 0) if mm.group(2) else 0
                t = base + imm
                for name, (lo, hi) in RANGES.items():
                    if lo <= t < hi:
                        hits.append((x.address, f'{x.mnemonic} {x.op_str}', t, name))
            if dst == reg:
                break
            continue
        if dst == reg and not x.mnemonic.startswith('ldr'):
            break
        if x.mnemonic in ('bl', 'b', 'ret', 'br', 'blr'):
            break
for site, text, t, name in hits[:60]:
    emit(f'   {site:08x}  {text:<32} → {t:#x} ({name})')
out['hits_5_30'] = [{'site': hex(s), 'insn': t, 'target': hex(a_), 'range': n} for s, t, a_, n in hits[:80]]

(HERE / 'писатели_флага.txt').write_text('\n'.join(lines) + '\n', encoding='utf8')
(HERE / 'писатели_флага.json').write_text(json.dumps(out, ensure_ascii=False, indent=1), encoding='utf8')
print('saved писатели_флага.txt/.json')
