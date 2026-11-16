# -*- coding: utf-8 -*-
"""D: структурный diff функции подготовки кадра X-H2 (одна и та же функция).

old 0x2cecf2c..0x2cedfc0 (0x1094 Б), new 0x2ce8f3c..0x2cea030 (0x10F4 Б).
Крупные иммедиаты (>=0x1000: adrp-страницы, цели bl/b) маскируются в <A>,
небольшие смещения структур (#0x60, #0x84, #0x1a …) сохраняются. Так видны
только реальные правки, а не сдвиг адресов при перекомпоновке.
"""
import sys, re, difflib, json
sys.path.insert(0, r'<корень проекта>\Анализ_прошивки\Сравнение_версий_2026-11-16\D_брекетинг')
from dhelp import *  # noqa

def text(b, start, end):
    out = []
    for x in all_insns(b, start, end):
        if x.mnemonic == '.byte':
            continue
        ops = re.sub(r'#0x([0-9a-f]+)',
                     lambda m: '#0x%x' % int(m.group(1), 16) if int(m.group(1), 16) < 0x1000 else '<A>',
                     x.op_str)
        out.append((x.address, f'{x.mnemonic} {ops}'))
    return out

o = text(load('X-H2', 'old', 1), 0x2cecf2c, 0x2cedfc4)
n = text(load('X-H2', 'new', 1), 0x2ce8f3c, 0x2cea034)
print(f'old {len(o)} инстр., new {len(n)} инстр., байт {len(o)*4:#x} / {len(n)*4:#x}')
so, sn = [t for _, t in o], [t for _, t in n]
sm = difflib.SequenceMatcher(None, so, sn, autojunk=False)
hunks = []
for tag, i1, i2, j1, j2 in sm.get_opcodes():
    if tag == 'equal':
        continue
    hunks.append({'tag': tag, 'old_range': [i1, i2], 'new_range': [j1, j2],
                  'old_addr': hex(o[i1][0]) if i1 < len(o) else hex(o[-1][0]),
                  'new_addr': hex(n[j1][0]) if j1 < len(n) else hex(n[-1][0]),
                  'old': so[i1:i2], 'new': sn[j1:j2]})
    print(f'\n### {tag}: old[{i1}:{i2}] @ {hunks[-1]["old_addr"]} -> new[{j1}:{j2}] @ {hunks[-1]["new_addr"]}')
    for k in range(max(0, i1 - 2), i1):
        print(f'    .. {so[k]}')
    for s in so[i1:i2]:
        print('  - ', s)
    for s in sn[j1:j2]:
        print('  + ', s)
print(f'\nвсего различающихся блоков: {len(hunks)}')
json.dump(hunks, open('prep_diff_hunks.json', 'w', encoding='utf8'), ensure_ascii=False, indent=1)
