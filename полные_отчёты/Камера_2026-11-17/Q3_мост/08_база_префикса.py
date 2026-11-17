# -*- coding: utf-8 -*-
"""Q3 шаг 8: подбор базы ПРЕФИКСА для сервисов 0x5460C/0x4A458/0x57670/0x50D94."""
import struct
import sys
from pathlib import Path

HERE = Path(__file__).resolve().parent
sys.path.insert(0, str(HERE))
from q3common import prefix, dis  # noqa: E402

p = prefix()
targets = {'resolver': 0x5460C, 'dispatcher': 0x4A458, 'logger': 0x57670, 'scalar': 0x50D94}


def is_prologue(o):
    if o < 0 or o + 4 > len(p.data):
        return False
    w = struct.unpack_from('<I', p.data, o)[0]
    return (w & 0xffc07fff) == 0xa9807bfd


cands = []
for B in range(0x10000, 0x55000, 0x1000):
    offs = {k: va - B for k, va in targets.items()}
    if any(o < 0 or o >= 0x40000 for o in offs.values()):
        continue
    score = sum(is_prologue(o) for o in offs.values())
    cands.append((score, B, offs))
cands.sort(reverse=True)
for score, B, offs in cands[:10]:
    print(f'B={B:#x} prologues={score}/4 ' + ' '.join(f'{k}={o:#x}' for k, o in offs.items()))
print()
for score, B, offs in cands[:3]:
    print(f'===== prefix B={B:#x} =====')
    for k, o in offs.items():
        print(f'--- {k} @ prefix off {o:#x} ---')
        print(dis(p, o, 16))
        print()
