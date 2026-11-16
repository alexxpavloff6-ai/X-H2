"""60: хранилище записей: геттер 0x14C6384, его соседи (сеттер?), резолвер 0x5460C, таблица.

План:
 * полный дизасм геттера 0x14C6384 (block0 new) до конца функции;
 * соседние функции 0x14C6434, 0x14C9564, 0x14C4DA4 — дизасм;
 * дизасм резолвера 0x5460C в блоке 2 (там другая база, поэтому раньше пусто);
 * поиск таблицы записей: что возвращает резолвер (ptr в [sp+0x38]) и откуда.

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

lines = []


def emit(s=''):
    print(s)
    lines.append(s)


def dump(blk, lo, hi, tag):
    emit(f'--- {tag}: {blk.version} block{blk.idx} [{lo:#x}..{hi:#x})')
    for x in fwcommon.insns(blk, lo, (hi - lo) // 4):
        emit(f'  {x.address:08x}  {x.bytes.hex():<10} {x.mnemonic:<8} {x.op_str}')


b0 = fwcommon.load('X-H2', 'new', 0)
b1 = fwcommon.load('X-H2', 'new', 1)
b2 = fwcommon.load('X-H2', 'new', 2)
b3 = fwcommon.load('X-H2', 'new', 3)

dump(b0, 0x14C6384, 0x14C6434, 'геттер целиком')
dump(b0, 0x14C6434, 0x14C64C0, 'сосед +0xB0')
dump(b0, 0x14C9564, 0x14C9600, 'функция 0x14C9564 (копия payload?)')
dump(b2, 0x5460C, 0x54648, 'резолвер 0x5460C (block2)')

(HERE / 'хранилище_записей.txt').write_text('\n'.join(lines) + '\n', encoding='utf8')
print('saved хранилище_записей.txt')
