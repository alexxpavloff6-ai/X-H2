# -*- coding: utf-8 -*-
"""Q3 шаг 15: писатели фактического затвора (base 0x2299498 + 0x19AC) и
обращения к params-контейнерам записи 0x4C в блоках 0/1."""
import json
import re
import sys
from pathlib import Path

HERE = Path(__file__).resolve().parent
sys.path.insert(0, str(HERE))
from q3common import load, dis, insns, adrp_refs, func_start  # noqa: E402

BASE = 0x2299498
OFF_SHUTTER = 0x19AC
OFF_SPEED = 0x1994


def find_base_offset_access(b, base, off, kind='str'):
    """Ищем adr p+add -> base, затем str/ldr [reg,#off] (callee-saved reg живёт через bl)."""
    hits = []
    # все ADRP на страницу base
    from q3common import adrp_sites
    for va, reg in adrp_sites(b, base):
        r = f'x{reg}'
        # проверяем add reg,reg,#(base&0xfff)
        got_base = False
        for ins in insns(b, va, 3):
            if ins.mnemonic == 'add' and ins.op_str.startswith(f'{r}, {r}, #'):
                imm = int(ins.op_str.split('#')[1], 0)
                if (base & ~0xfff) + imm == base:
                    got_base = True
                break
        if not got_base:
            continue
        # ищем доступ [r,#off] вперёд до 600 инструкций
        for ins in insns(b, va + 4, 600):
            if ins.mnemonic in ('str', 'ldr', 'stur', 'ldur') and f'[{r}, #0x{off:x}]' in ins.op_str:
                k = 'w' if ins.mnemonic.startswith('str') else 'r'
                hits.append({'adrp': hex(va), 'access': hex(ins.address), 'kind': k,
                             'insn': f'{ins.address:x}: {ins.mnemonic} {ins.op_str}',
                             'func': hex(func_start(b, ins.address) or 0)})
            if ins.mnemonic == 'ret':
                break
    return hits


out = []
result = {}
for idx in (0, 1):
    b = load('X-H2', 'old', idx)
    sh = find_base_offset_access(b, BASE, OFF_SHUTTER)
    sp = find_base_offset_access(b, BASE, OFF_SPEED)
    result[f'block{idx}'] = {'shutter_0x19AC': sh, 'speed_0x1994': sp}
    out.append(f'=== block{idx}: доступ к 0x2299498+0x19AC (фактический затвор): {len(sh)} ===')
    for h in sh:
        out.append(f"  {h['kind']} {h['insn']}  func={h['func']}")
    out.append(f'=== block{idx}: доступ к 0x2299498+0x1994 (выдержка output): {len(sp)} ===')
    for h in sp:
        out.append(f"  {h['kind']} {h['insn']}  func={h['func']}")
    out.append('')

# params-контейнеры записи 0x4C
for name, tgt in (('pending', 0x4C3F090), ('current', 0x4C3F1F8),
                  ('pending_payload', 0x4C3F0A0), ('current_payload', 0x4C3F208)):
    result[name] = {}
    for idx in (0, 1):
        b = load('X-H2', 'old', idx)
        rows = adrp_refs(b, tgt, window=20)
        result[name][f'block{idx}'] = rows
        out.append(f'=== {name} {tgt:#x} block{idx}: {len(rows)} ===')
        for r in rows:
            out.append('  ' + r['insn'])
    out.append('')

text = '\n'.join(out)
(HERE / 'писатели_факт_затвора.txt').write_text(text + '\n', encoding='utf-8')
(HERE / 'писатели_факт_затвора.json').write_text(json.dumps(result, ensure_ascii=False, indent=2) + '\n', encoding='utf-8')
print(text)
