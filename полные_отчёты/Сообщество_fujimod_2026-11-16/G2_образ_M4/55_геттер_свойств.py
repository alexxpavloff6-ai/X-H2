"""55: что за вызов 0x14C6384(w0=0x4C, x1=0x4C3B090, w2=-1) — геттер свойства/настроек?
И что делает 0x3101108 перед ним. Ищем таблицу свойств и id 0x4C.

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

b = fwcommon.load('X-H2', 'new', 1)
lines = []


def emit(s=''):
    print(s)
    lines.append(s)


def dump(lo, hi, tag):
    emit(f'--- {tag} [{lo:#x}..{hi:#x})')
    for x in fwcommon.insns(b, lo, (hi - lo) // 4):
        emit(f'  {x.address:08x}  {x.bytes.hex():<10} {x.mnemonic:<8} {x.op_str}')


dump(0x14C6384, 0x14C6484, '0x14C6384 (вызывается с id=0x4C)')
dump(0x3101108, 0x31011D0, '0x3101108 (перед геттером)')

# кто ещё вызывает 0x14C6384 и с какими id
calls = fwcommon.bl_callers(b, 0x14C6384)
emit(f'\n== всего вызовов 0x14C6384: {len(calls)}')
for site, kind in calls[:40]:
    seq = fwcommon.insns(b, site - 0x10, 5)
    txt = ' | '.join(f'{x.mnemonic} {x.op_str}' for x in seq)
    emit(f'  {site:08x}: {txt}')

(HERE / 'геттер_свойств.txt').write_text('\n'.join(lines) + '\n', encoding='utf8')
print('saved геттер_свойств.txt')
