# -*- coding: utf-8 -*-
"""Q3 шаг 11: поиск обращений к UI_SETP-номерам сценария в блоках 0/1.
Ищем movz w<rd>,#<id> и ближайший bl — чтобы найти property get/set API
и функции, читающие несколько свойств сценария одновременно."""
import json
import struct
import sys
from pathlib import Path

HERE = Path(__file__).resolve().parent
sys.path.insert(0, str(HERE))
from q3common import load, insns, func_start  # noqa: E402

IDS = {
    0xB: 'REC_VIEW',
    0x827: 'SHUTTER_TYPE',
    0x858: 'CONTINUOUS',
    0xAAB: 'DOTLCD_SHUTERSPEED_OUTPUT',
    0xAB8: 'DOTLCD_SHUTTERTYPE_OUTPUT',
    0xAC7: 'DOTLCD_SHUTTERTYPE',
    0xACE: 'DOTLCD_CONTINUOUS',
    0xACF: 'DOTLCD_CONTINUOUS2',
    0x8A0: 'SHUTTER_SPEED_M',
    0x89E: 'SHUTTER_SPEED',
}

rows = []
for idx in (0, 1):
    b = load('X-H2', 'old', idx)
    for o in range(0, len(b.data) - 3, 4):
        w = struct.unpack_from('<I', b.data, o)[0]
        if (w & 0xFFE00000) != 0x52800000:  # movz w<rd>,#imm16 (hw=0)
            continue
        imm = (w >> 5) & 0xFFFF
        if imm not in IDS:
            continue
        rd = w & 31
        va = b.base + o
        # ближайший bl в следующих 6 инструкциях
        nxt = insns(b, va + 4, 6)
        bl = None
        for ins in nxt:
            if ins.mnemonic in ('bl', 'b'):
                bl = ins.op_str
                break
            if ins.mnemonic == 'ret':
                break
        fs = func_start(b, va)
        rows.append({'block': idx, 'va': hex(va), 'id': hex(imm), 'name': IDS[imm],
                     'reg': f'w{rd}', 'next_branch': bl, 'func': hex(fs) if fs else None})

# группировка по функции: какие id встречаются вместе
byfunc = {}
for r in rows:
    byfunc.setdefault((r['block'], r['func']), set()).add(r['name'])
multi = {f'{b}:{f}': sorted(names) for (b, f), names in byfunc.items() if len(names) >= 2}

result = {'total_sites': len(rows), 'sites': rows, 'functions_with_multiple_scenario_ids': multi}
(HERE / 'свойства_сценария.json').write_text(json.dumps(result, ensure_ascii=False, indent=2) + '\n', encoding='utf-8')
print('всего сайтов movz с id сценария:', len(rows))
print('функции с >=2 id сценария:')
for f, names in sorted(multi.items()):
    print(' ', f, names)
print()
print('первые 40 сайтов:')
for r in rows[:40]:
    print(' ', r['block'], r['va'], r['name'], r['reg'], '->', r['next_branch'], 'func', r['func'])
