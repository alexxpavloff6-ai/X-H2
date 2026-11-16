"""61: все MOVZ-константы 0x4C и 0x168 в блоках 0-2 (обе версии) + контекст.

Идея: сеттер/геттер записи вызывается с id=0x4C; если литерал где-то есть — увидим.
Также ищем размер 0x168 (размер payload нашей записи).

Только чтение.
"""
import sys
from pathlib import Path

import numpy as np

HERE = Path(__file__).resolve().parent
sys.path.insert(0, str(HERE))
import m4lib

sys.path.insert(0, str(m4lib.ANALYSIS / 'Сравнение_версий_2026-11-16'))
import fwcommon

lines = []


def emit(s=''):
    print(s)
    lines.append(s)


for state in ('new', 'old'):
    for idx in (0, 1, 2):
        b = fwcommon.load('X-H2', state, idx)
        a = np.frombuffer(b.data[:len(b.data) & ~3], dtype='<u4').astype(np.uint64)
        for imm in (0x4C, 0x168):
            m = ((a & 0xFFE00000) == 0x52800000) & (((a >> 5) & 0xFFFF) == imm)
            sites = [b.base + int(i) * 4 for i in np.nonzero(m)[0]]
            emit(f'== {b.version} block{idx}: MOVZ #0x{imm:x}: {len(sites)} '
                 f'{[hex(s) for s in sites[:12]]}')
            for s in sites[:6]:
                emit(f'--- {s:#x}')
                for x in fwcommon.insns(b, s - 0x10, 12):
                    mark = ' <==' if x.address == s else ''
                    emit(f'    {x.address:08x}  {x.bytes.hex():<10} {x.mnemonic:<8} {x.op_str}{mark}')

(HERE / 'литералы_4c_168.txt').write_text('\n'.join(lines) + '\n', encoding='utf8')
print('saved литералы_4c_168.txt')
