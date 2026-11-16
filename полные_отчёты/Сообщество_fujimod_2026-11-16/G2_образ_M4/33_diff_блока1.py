"""33: (а) побайтовый diff блока 1 old 5.30 vs new 5.33 (карта изменений);
(б) все str/ldr с смещениями 0xD0/0xD8/0xF0/0x114 в блоке 1 (обе версии) + контекст;
(в) код вокруг ссылки на запись таблицы карты регистров (old VA 0x2ebbcb0 → 0x385E1B0).

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


old = fwcommon.load('X-H2', 'old', 1)
new = fwcommon.load('X-H2', 'new', 1)
emit(f'old base={old.base:#x} len={len(old.data):#x}; new base={new.base:#x} len={len(new.data):#x}')

# ---------------------------------------------------------------- (а) diff
n = min(len(old.data), len(new.data))
a = np.frombuffer(old.data[:n], dtype=np.uint8)
b = np.frombuffer(new.data[:n], dtype=np.uint8)
d = a != b
idx = np.nonzero(d)[0]
emit(f'\n== (а) различающихся байт: {len(idx)} из {n} ({100 * len(idx) / n:.3f}%)')
# кластеры: разрывы > 0x40
clusters = []
if len(idx):
    start = prev = int(idx[0])
    for i in idx[1:]:
        i = int(i)
        if i - prev > 0x40:
            clusters.append((start, prev))
            start = i
        prev = i
    clusters.append((start, prev))
emit(f'   кластеров (разрыв >0x40): {len(clusters)}')
for s, e in clusters[:40]:
    emit(f'   off {s:#08x}..{e:#08x} ({e - s + 1:#x} байт) → old VA {old.base + s:#x}..{old.base + e:#x}'
         f' | new VA {new.base + s:#x}..{new.base + e:#x}')
out['diff_clusters'] = [{'off_start': hex(s), 'off_end': hex(e), 'len': e - s + 1,
                          'old_va': hex(old.base + s), 'new_va': hex(new.base + s)} for s, e in clusters]

# ---------------------------------------------------------------- (б) смещения MOVDC
emit('\n== (б) обращения к +0xD0/+0xD8/+0xF0/+0x114 в блоке 1 (new 5.33)')
KEY = {0xD0: 'stride', 0xD8: 'mode', 0xF0: '+0xF0', 0x18: 'size', 0x114: 'status'}
for b, tag in ((new, 'new'), (old, 'old')):
    hits = []
    for x in fwcommon.insns(b, b.base, len(b.data) // 4):
        if x.mnemonic.startswith(('str', 'ldr')):
            m = re.search(r'\[(x\d+|w\d+|sp)(?:, #(0x[0-9a-f]+|\d+))?\]', x.op_str)
            if m and m.group(2):
                off = int(m.group(2), 0)
                if off in KEY:
                    hits.append((x.address, x.mnemonic, x.op_str, off))
    emit(f'  {tag}: {len(hits)} обращений')
    for a_, m_, o_, off in hits[:25]:
        emit(f'    {a_:08x}  {m_:<8} {o_:<28} (+{off:#x} {KEY[off]})')
    out[f'hits_{tag}'] = [{'va': hex(a_), 'insn': f'{m_} {o_}', 'off': hex(off)} for a_, m_, o_, off in hits[:80]]

# ---------------------------------------------------------------- (в) код у ссылки на таблицу
emit('\n== (в) old 5.30: код вокруг ссылки на запись таблицы (adrp 0x2ebbcb0 → 0x385E1B0)')
for x in fwcommon.insns(old, 0x2EBBC60, 0x140 // 4):
    emit(f'  {x.address:08x}  {x.bytes.hex():<10} {x.mnemonic:<8} {x.op_str}')

(HERE / 'diff_блока1.txt').write_text('\n'.join(lines) + '\n', encoding='utf8')
(HERE / 'diff_блока1.json').write_text(json.dumps(out, ensure_ascii=False, indent=1), encoding='utf8')
print('saved diff_блока1.txt/.json')
