# -*- coding: utf-8 -*-
"""Локальный helper для задачи E: свойство 0x2B9, значение 0x2C.

fwcommon не меняем — импортируем и добавляем своё.
"""
import sys, re, struct
sys.path.insert(0, r'<корень проекта>\Анализ_прошивки\Сравнение_версий_2026-11-16')
from fwcommon import *  # noqa
from capstone import Cs, CS_ARCH_ARM64, CS_MODE_LITTLE_ENDIAN

_cs2 = Cs(CS_ARCH_ARM64, CS_MODE_LITTLE_ENDIAN)
_cs2.skipdata = True
_cs2.detail = False


def all_insns(b, start=None, end=None):
    start = b.base if start is None else start
    end = b.end if end is None else end
    o = b.off(start)
    return _cs2.disasm(b.data[o:b.off(end)], start)


def func_insns(b, start, maxbytes=0x6000):
    out = []
    for x in all_insns(b, start, min(start + maxbytes, b.end)):
        if x.mnemonic == '.byte':
            continue
        out.append(x)
        if x.mnemonic == 'ret':
            nxt = [y for y in all_insns(b, x.address + 4, min(x.address + 0x40, b.end))
                   if y.mnemonic != '.byte'][:1]
            if nxt and nxt[0].mnemonic == 'stp' and 'sp, #-' in nxt[0].op_str:
                break
    return out


def imm(x):
    m = re.search(r'#(-?0x[0-9a-f]+|-?\d+)', x.op_str)
    return int(m.group(1), 0) if m else None


def find_prologue(b, va, limit=0x8000):
    """Начало функции: stp x29,x30,[sp,#-N]! + mov x29,sp."""
    for a in range(va & ~3, max(b.base, va - limit), -4):
        w = struct.unpack_from('<I', b.data, b.off(a))[0]
        if (w & 0xffc07fff) == 0xa9807bfd:
            nxt = list(insns(b, a + 4, 1))
            if nxt and nxt[0].mnemonic == 'mov' and nxt[0].op_str == 'x29, sp':
                return a
    return None


def dump_range(b, start, end, skip_bytes=True):
    for x in all_insns(b, start, end):
        if skip_bytes and x.mnemonic == '.byte':
            continue
        print(f'{x.address:x}: {x.mnemonic:8} {x.op_str}')


def movz_id_before(b, va, back=0x60):
    """Ищем mov wN,#imm / orr в пределах back байт перед va; возвращаем (reg, imm3)."""
    out = []
    for x in all_insns(b, va - back, va):
        if x.mnemonic == '.byte':
            continue
        if x.mnemonic in ('mov', 'movz', 'movn', 'orr') and re.match(r'w\d+, #', x.op_str):
            reg, val = x.op_str.split(', ')
            out.append((x.address, reg, int(val, 0)))
    return out


def bl_sites(b):
    """Все bl/b с целью: dict target -> [(site, kind)]."""
    res = {}
    data, base = b.data, b.base
    for o in range(0, len(data) - 3, 4):
        w = struct.unpack_from('<I', data, o)[0]
        if (w & 0x7c000000) == 0x14000000:
            i = w & 0x3ffffff
            if i & (1 << 25):
                i -= 1 << 26
            t = base + o + i * 4
            res.setdefault(t, []).append((base + o, 'bl' if w & 0x80000000 else 'b'))
    return res


def u16(b, va):
    return struct.unpack_from('<H', b.data, b.off(va))[0]


def u32(b, va):
    return struct.unpack_from('<I', b.data, b.off(va))[0]


def u64v(b, va):
    return struct.unpack_from('<Q', b.data, b.off(va))[0]


def hx(a):
    return f'{a:#x}'
