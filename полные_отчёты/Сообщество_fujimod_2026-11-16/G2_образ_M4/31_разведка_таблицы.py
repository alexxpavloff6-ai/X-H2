"""31: разведка — где именно код, работающий с таблицей карты регистров 0x385E1xx.

* ADRP на страницы 0x385E000/0x385D000 во всех блоках 0-2 (old/new);
* дизасм вокруг VA 0x2f6a510 (блок 1, как указал координатор) в обеих версиях;
* дизасм вокруг самих ADRP-сайтов (0x2ebb4e0 old / 0x2ebb0e0 new) — там цикл по 8 записям.

Только чтение.
"""
import json
import sys
from pathlib import Path

HERE = Path(__file__).resolve().parent
sys.path.insert(0, str(HERE))
import m4lib

sys.path.insert(0, str(m4lib.ANALYSIS / 'Сравнение_версий_2026-11-16'))
import fwcommon

lines = []


def emit(s=''):
    print(s)
    lines.append(s)


def probe_block(state, idx, pages=(0x385E000, 0x385D000)):
    b = fwcommon.load('X-H2', state, idx)
    emit(f'== X-H2 {b.version} block{idx} base={b.base:#x} len={len(b.data):#x}')
    for p in pages:
        sites = fwcommon.adrp_sites(b, p)
        emit(f'   ADRP на {p:#x}: {len(sites)} ' +
             ', '.join(f'{s:#x}(x{r})' for s, r in sites[:12]))
    return b


for state in ('old', 'new'):
    for idx in (0, 1, 2):
        probe_block(state, idx)

EMIT = 0x60


def window(b, va, before=0x30, after=0xE0):
    emit(f'--- {b.model} {b.version} b{b.idx} VA {va:#x}')
    for x in fwcommon.insns(b, va - before, (before + after) // 4):
        mark = ' <==' if x.address == va else ''
        emit(f'  {x.address:08x}  {x.bytes.hex():<10} {x.mnemonic:<8} {x.op_str}{mark}')


for state in ('old', 'new'):
    b = fwcommon.load('X-H2', state, 1)
    window(b, 0x2F6A510, 0x40, 0x100)

(HERE / 'разведка_таблицы.txt').write_text('\n'.join(lines) + '\n', encoding='utf8')
print('saved разведка_таблицы.txt')
