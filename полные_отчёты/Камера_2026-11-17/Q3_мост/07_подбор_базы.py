# -*- coding: utf-8 -*-
"""Q3 шаг 7: подбор базы блока 2. Цели вызовов из блока 0: резолвер 0x5460C,
диспетчер 0x4A458, логгер 0x57670, скаляр 0x50D94. Для кандидата B2 проверяем,
что block2[VA-B2] начинается с пролога/кода. Печатаем лучшие кандидаты."""
import struct
import sys
from pathlib import Path

HERE = Path(__file__).resolve().parent
sys.path.insert(0, str(HERE))
from q3common import load, dis  # noqa: E402

b2 = load('X-H2', 'old', 2)
targets = {'resolver': 0x5460C, 'dispatcher': 0x4A458, 'logger': 0x57670, 'scalar': 0x50D94}


def is_prologue(o):
    if o < 0 or o + 4 > len(b2.data):
        return False
    w = struct.unpack_from('<I', b2.data, o)[0]
    return (w & 0xffc07fff) == 0xa9807bfd  # stp x29,x30,[sp,#-N]!


def first_word(o):
    if o < 0 or o + 4 > len(b2.data):
        return None
    return struct.unpack_from('<I', b2.data, o)[0]


cands = []
for B2 in range(0, 0x55000, 0x1000):
    offs = {k: va - B2 for k, va in targets.items()}
    if any(o < 0x10 for o in offs.values()):
        continue
    score = sum(is_prologue(o) for o in offs.values())
    cands.append((score, B2, offs))

cands.sort(reverse=True)
for score, B2, offs in cands[:12]:
    print(f'B2={B2:#x} prologues={score}/4 offs=' + ' '.join(f'{k}={o:#x}' for k, o in offs.items()))

print()
for score, B2, offs in cands[:4]:
    print(f'===== B2={B2:#x} =====')
    for k, o in offs.items():
        print(f'--- {k} @ block2 off {o:#x} ---')
        print(dis(b2, o, 14))
        print()
