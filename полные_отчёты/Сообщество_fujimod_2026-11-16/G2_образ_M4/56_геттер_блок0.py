"""56: геттер свойств 0x14C6384 живёт в блоке 0 — разбираем; ищем сеттер свойства 0x4C и его размер.

* дизасм 0x14C6384 (блок 0, new);
* все вызовы 0x14C6384 с w0 = 0x4C и что вокруг;
* поиск в блоке 0 вызовов вида `mov w0,#0x4C ... bl <func>` (сеттеры/геттеры свойства 0x4C);
* поиск memcpy с size 0x168 (размер pending-параметров).

Только чтение.
"""
import re
import sys
from pathlib import Path

HERE = Path(__file__).resolve().parent
sys.path.insert(0, str(HERE))
import m4lib

sys.path.insert(0, str(m4lib.ANALYSIS / 'Сравнение_версий_2026-11-16'))
import fwcommon

b = fwcommon.load('X-H2', 'new', 0)
lines = []


def emit(s=''):
    print(s)
    lines.append(s)


def dump(lo, hi, tag, bb=None):
    bb = bb or b
    emit(f'--- {tag} [{lo:#x}..{hi:#x})')
    for x in fwcommon.insns(bb, lo, (hi - lo) // 4):
        emit(f'  {x.address:08x}  {x.bytes.hex():<10} {x.mnemonic:<8} {x.op_str}')


emit('== геттер 0x14C6384 (блок 0)')
dump(0x14C6384, 0x14C63E4, 'getter head')

emit('\n== вызовы 0x14C6384, где w0 = 0x4C или 0x4D')
calls = fwcommon.bl_callers(b, 0x14C6384)
n = 0
for site, kind in calls:
    seq = fwcommon.insns(b, site - 0x10, 5)
    txt = [f'{x.mnemonic} {x.op_str}' for x in seq]
    if any('w0, #0x4c' in t or 'w0, #0x4d' in t or 'w0, #0x4b' in t for t in txt):
        emit(f'  {site:08x}: ' + ' | '.join(txt))
        n += 1
emit(f'  найдено: {n}')

emit('\n== где ещё в блоке 0 фигурирует id 0x4C рядом с вызовами (первые 20)')
import numpy as np
a = np.frombuffer(b.data[:len(b.data) & ~3], dtype='<u4').astype(np.uint64)
# movz w0,#0x4c: 0x52800000|0x4c<<5
m = ((a & 0xFFE0001F) == (0x52800000 | (0x4C << 5)))
sites = [b.base + int(i) * 4 for i in np.nonzero(m)[0]]
emit(f'  movz w0,#0x4c: {len(sites)} сайтов; первые: {[hex(s) for s in sites[:12]]}')

emit('\n== memcpy с размером 0x168 в блоке 0 и блоке 1')
for blk in (fwcommon.load('X-H2', 'new', 0), fwcommon.load('X-H2', 'new', 1)):
    aa = np.frombuffer(blk.data[:len(blk.data) & ~3], dtype='<u4').astype(np.uint64)
    m = ((aa & 0xFFE0001F) == (0x52800000 | (0x168 << 5)))
    emit(f'  block{blk.idx}: movz w2/w?, #0x168: {int(m.sum())} сайтов')

(HERE / 'геттер_блок0.txt').write_text('\n'.join(lines) + '\n', encoding='utf8')
print('saved геттер_блок0.txt')
