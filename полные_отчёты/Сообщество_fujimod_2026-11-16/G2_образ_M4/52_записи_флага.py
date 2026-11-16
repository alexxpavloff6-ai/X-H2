"""52: ветка 2 — кто ПИШЕТ guard-флаг 0x4C2FF14 и поле +0x74 в структурах params.

Метод: линейный трекер по ADRP+ADD в блоках 0-2 (old/new). Для каждой пары (ADRP, ADD) получаем
абсолютную базу; затем в пределах 60 инструкций следим за регистром-базой (пока его не перезапишут)
и собираем все STR/STRB/STP в абсолютные адреса. Оставляем только попадания в интересующие диапазоны:
  A) pending params  = 0x4C3B090..0x4C3B1F8
  B) current params  = 0x4C3B1F8..0x4C3B360
  C) state params    = 0x4C2FEA0..0x4C30000  (флаг 0x4C2FF14 = 0x4C2FAD8+0x43C = 0x4C2FEA0+0x74)
  D) 0x4C3F090..0x4C3F200

Печатаем сайт, инструкцию и смещение поля. Только чтение.
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

RANGES = {
    'pending_params': (0x4C3B090, 0x4C3B1F8),
    'current_params': (0x4C3B1F8, 0x4C3B360),
    'state_params': (0x4C2FEA0, 0x4C30000),
    'копия_4C3F090': (0x4C3F090, 0x4C3F200),
}
TARGETS = {'флаг_0x4C2FF14': 0x4C2FF14, 'pending_+0x74': 0x4C3B104, 'current_+0x74': 0x4C3B26C}

lines = []
out = {}


def emit(s=''):
    print(s)
    lines.append(s)


def absolute_stores(b, window=60):
    """Возвращает список (site, insn_text, target) для store в абсолютные адреса."""
    a = np.frombuffer(b.data[:len(b.data) & ~3], dtype='<u4').astype(np.uint64)
    adrp_idx = np.nonzero((a & 0x9F000000) == 0x90000000)[0]
    res = []
    for i in adrp_idx:
        site = b.base + int(i) * 4
        seq = fwcommon.insns(b, site, 3)
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
        # следим за регистром
        for x in fwcommon.insns(b, seq[1].address + 4, window):
            dst = x.op_str.split(',')[0].strip() if x.op_str else ''
            if x.mnemonic.startswith(('str', 'stp')):
                mm = re.search(r'\[(x\d+|w\d+|sp)(?:, #(0x[0-9a-f]+|\d+))?\]', x.op_str)
                if mm and mm.group(1) == reg:
                    imm = int(mm.group(2), 0) if mm.group(2) else 0
                    res.append((x.address, f'{x.mnemonic} {x.op_str}', base + imm))
                if dst == reg:
                    break
                continue
            if dst == reg and not x.mnemonic.startswith('ldr'):
                break
            if x.mnemonic in ('bl', 'b', 'ret', 'br', 'blr'):
                break
    return res


for state in ('new', 'old'):
    for idx in (0, 1, 2):
        b = fwcommon.load('X-H2', state, idx)
        emit(f'== X-H2 {b.version} block{idx}')
        stores = absolute_stores(b)
        hits = []
        for site, text, tgt in stores:
            for name, (lo, hi) in RANGES.items():
                if lo <= tgt < hi:
                    hits.append({'site': hex(site), 'insn': text, 'target': hex(tgt),
                                 'range': name, 'field_off': hex(tgt - lo)})
            for name, t in TARGETS.items():
                if tgt == t:
                    hits.append({'site': hex(site), 'insn': text, 'target': hex(tgt),
                                 'range': name, 'field_off': '0x0'})
        if hits:
            for h in hits:
                emit(f"   {h['site']}  {h['insn']:<34} → {h['target']} ({h['range']}, +{h['field_off']})")
        else:
            emit('   прямых записей в эти диапазоны нет')
        out[f'{state}{idx}'] = hits

(HERE / 'записи_флага.txt').write_text('\n'.join(lines) + '\n', encoding='utf8')
(HERE / 'записи_флага.json').write_text(json.dumps(out, ensure_ascii=False, indent=1), encoding='utf8')
print('saved записи_флага.txt/.json')
