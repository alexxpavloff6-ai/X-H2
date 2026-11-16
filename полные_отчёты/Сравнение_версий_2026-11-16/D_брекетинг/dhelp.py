# -*- coding: utf-8 -*-
"""Локальный helper для задачи D: полное дизассемблирование блока с пропуском
невалидных слов (capstone skipdata), поиск обращений к структурам по смещению,
чтение blob-образа параметров и мелкие утилиты сравнения.

fwcommon не меняем — импортируем его и добавляем своё.
"""
import sys, re, struct
sys.path.insert(0, r'<корень проекта>\Анализ_прошивки\Сравнение_версий_2026-11-16')
from fwcommon import *  # noqa
from capstone import Cs, CS_ARCH_ARM64, CS_MODE_LITTLE_ENDIAN

_cs2 = Cs(CS_ARCH_ARM64, CS_MODE_LITTLE_ENDIAN)
_cs2.skipdata = True
_cs2.detail = False


def all_insns(b, start=None, end=None):
    """Все инструкции блока (с пропуском невалидных 4-байтовых слов)."""
    start = b.base if start is None else start
    end = b.end if end is None else end
    o = b.off(start)
    return _cs2.disasm(b.data[o:b.off(end)], start)


def mem_refs(b, imm, kinds=('ldr', 'str', 'ldrh', 'strh', 'ldrb', 'strb',
                            'ldrsw', 'ldrsb', 'ldrsh', 'ldur', 'stur',
                            'ldurh', 'sturh', 'ldp', 'stp', 'ldpsw')):
    """Инструкции с операндом памяти [xN, #imm] (imm точно равен)."""
    pat = re.compile(r'\[x\d+, #0x%x\]' % imm)
    out = []
    for x in all_insns(b):
        if x.mnemonic in kinds and pat.search(x.op_str):
            out.append(x)
    return out


def func(b, start, maxbytes=0x8000):
    """Инструкции функции: до ret, за которым следует новый пролог."""
    out = []
    for x in all_insns(b, start, start + maxbytes):
        if x.mnemonic == '.byte':
            continue
        out.append(x)
        if x.mnemonic == 'ret':
            nxt = [y for y in all_insns(b, x.address + 4, x.address + 0x40) if y.mnemonic != '.byte'][:1]
            if nxt and nxt[0].mnemonic == 'stp' and 'sp, #-' in nxt[0].op_str:
                break
    return out


def find_func_by_bytes(model, state, idx, bytes_hex, what=''):
    """Найти функцию в блоке по байтовому образцу (hex-строка)."""
    b = load(model, state, idx)
    pat = bytes.fromhex(bytes_hex)
    return [hex(a) for a in find_bytes(b, pat)]


def u16(b, va):
    return struct.unpack_from('<H', b.data, b.off(va))[0]


def u32(b, va):
    return struct.unpack_from('<I', b.data, b.off(va))[0]


def dump(b, va, n=20):
    return dis(b, va, n)
