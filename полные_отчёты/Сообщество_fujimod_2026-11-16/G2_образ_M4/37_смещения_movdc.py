"""37: кто формирует смещения 0xD0/0xD8/0xF0 для MOVDC — поиск movz w?,#imm и записей
с регистровым смещением.

Ищем в блоках 1 и 0 (new 5.33 и old 5.30):
  * movz w?, #0xD0 / #0xD8 / #0xF0 (word & 0xFFE00000 == 0x52800000, imm16 = (w>>5)&0xFFFF);
  * для каждого сайта — ближайший bl и окно кода;
  * функции-кандидаты, где встречаются все три смещения.

Только чтение.
"""
import json
import sys
from pathlib import Path

import numpy as np

from capstone import Cs, CS_ARCH_ARM64, CS_MODE_LITTLE_ENDIAN

HERE = Path(__file__).resolve().parent
sys.path.insert(0, str(HERE))
import m4lib

sys.path.insert(0, str(m4lib.ANALYSIS / 'Сравнение_версий_2026-11-16'))
import fwcommon

cs = Cs(CS_ARCH_ARM64, CS_MODE_LITTLE_ENDIAN)
lines = []
out = {}


def emit(s=''):
    print(s)
    lines.append(s)


def dump(b, va, before=0x20, after=0x60):
    for x in fwcommon.insns(b, va - before, (before + after) // 4):
        emit(f'    {x.address:08x}  {x.bytes.hex():<10} {x.mnemonic:<8} {x.op_str}')


for state, idxs in (('new', (1, 0)), ('old', (1,))):
    for idx in idxs:
        b = fwcommon.load('X-H2', state, idx)
        a = np.frombuffer(b.data[:len(b.data) & ~3], dtype='<u4').astype(np.uint64)
        emit(f'== X-H2 {b.version} block{idx} base={b.base:#x}')
        for imm in (0xD0, 0xD8, 0xF0, 0x114):
            m = ((a & 0xFFE00000) == 0x52800000) & (((a >> 5) & 0xFFFF) == imm)
            hits = [b.base + int(i) * 4 for i in np.nonzero(m)[0]]
            emit(f'   movz w?, #{imm:#x}: {len(hits)} {[hex(h) for h in hits[:10]]}')
            out.setdefault(f'{state}{idx}', {})[f'movz_{imm:x}'] = [hex(h) for h in hits[:40]]
        # окна, где рядом есть все три movz
        sets = {}
        for imm in (0xD0, 0xD8, 0xF0):
            m = ((a & 0xFFE00000) == 0x52800000) & (((a >> 5) & 0xFFFF) == imm)
            sets[imm] = set(int(i) * 4 for i in np.nonzero(m)[0])
        if all(sets.values()):
            # ищем окна 0x400, где встречаются все три
            for base_off in range(0, len(b.data) - 0x400, 0x40):
                present = [off for off in (0xD0, 0xD8, 0xF0)
                           if any(base_off <= s < base_off + 0x400 for s in sets[off])]
                if len(present) == 3:
                    emit(f'   окно со всеми тремя: {b.base + base_off:#x}..{b.base + base_off + 0x400:#x}')
                    out.setdefault(f'{state}{idx}', {}).setdefault('windows', []).append(
                        hex(b.base + base_off))
                    break

# для самых интересных movz #0xD8 печатаем контекст (new block1)
b = fwcommon.load('X-H2', 'new', 1)
a = np.frombuffer(b.data[:len(b.data) & ~3], dtype='<u4').astype(np.uint64)
for imm in (0xD0, 0xD8, 0xF0):
    m = ((a & 0xFFE00000) == 0x52800000) & (((a >> 5) & 0xFFFF) == imm)
    hits = [b.base + int(i) * 4 for i in np.nonzero(m)[0]]
    for h in hits[:3]:
        emit(f'--- new b1 movz #{imm:#x} @ {h:#x}')
        dump(b, h, 0x10, 0x30)

(HERE / 'смещения_movdc.txt').write_text('\n'.join(lines) + '\n', encoding='utf8')
(HERE / 'смещения_movdc.json').write_text(json.dumps(out, ensure_ascii=False, indent=1), encoding='utf8')
print('saved смещения_movdc.txt/.json')
