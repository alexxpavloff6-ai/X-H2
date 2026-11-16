# -*- coding: utf-8 -*-
"""E4: кто ветвится в чанки 0x128c300..0x128c700 (диспетчер по id) и где пролог."""
import sys, re, struct
sys.path.insert(0, r'<корень проекта>\Анализ_прошивки\Сравнение_версий_2026-11-16\E_сеттер_0x2B9')
from ecommon import *  # noqa

MODEL, STATE = 'X-H2', 'new'
b = load(MODEL, STATE, 0)
LO, HI = 0x128c000, 0x128c800

print('=== ветвления с целью в 0x128c000..0x128c800 ===')
rows = []
for x in all_insns(b, b.base, b.end):
    if x.mnemonic == '.byte':
        continue
    if x.mnemonic.startswith('b') or x.mnemonic in ('cbz', 'cbnz', 'tbz', 'tbnz'):
        m = re.search(r'#0x([0-9a-f]+)', x.op_str)
        if m:
            t = int(m.group(1), 16)
            if LO <= t < HI:
                rows.append((x.address, t, f'{x.mnemonic} {x.op_str}'))
print('всего:', len(rows))
# сгруппируем по источнику «кластера»
for a, t, txt in rows:
    print(f'  {a:#x} -> {t:#x}   {txt}')

# пролог: ищем назад от 0x128c380 sub sp / stp
print('\n=== назад от 0x128c380: sub sp,sp / stp с sp ===')
n = 0
for a in range(0x128c380, max(b.base, 0x128c380 - 0x20000), -4):
    w = struct.unpack_from('<I', b.data, b.off(a))[0]
    # sub sp, sp, #imm  -> 0xd1000000 | (imm<<10) | (31<<5) | 31
    if (w & 0xff8003ff) == 0xd10003ff or (w & 0xffc003ff) == 0xd10003ff:
        print(f'  {a:#x}: word {w:#x} (sub sp,sp,#? imm={(((w>>10)&0xfff)):#x})')
        n += 1
    # stp x29,x30,[sp,#imm]
    if (w & 0xffc07fff) == 0xa9007bfd:
        print(f'  {a:#x}: stp x29,x30,[sp,#imm]')
        n += 1
    if n > 12:
        break
