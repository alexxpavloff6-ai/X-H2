# -*- coding: utf-8 -*-
"""Общие helper'ы Q3. Доступ к блокам 5.30 (fwcommon) и к низкоуровневому
ARM64-префиксу DAT (VA 0..0x1101000), где живут резолвер/диспетчер/логгер.

Префикс кэшируется в prefix_5.30.bin (производный файл, только чтение DAT).
"""
import struct
import sys
from pathlib import Path

HERE = Path(__file__).resolve().parent
CV = HERE.parents[1] / 'Сравнение_версий_2026-11-16'
sys.path.insert(0, str(CV))
import fwcommon
from fwcommon import load, dis, insns, bl_callers, adrp_refs, adrp_sites, func_start, find_bytes, iter_words  # noqa: E402,F401

DAT = HERE.parents[2] / 'FIRMWARE' / 'ver 5.30' / 'FWUP0028.DAT'
PREFIX_END = 0x300274  # начало первого FFLZ-блока


class Prefix:
    """Block-совместимый объект для префикса DAT, база 0."""
    def __init__(self, data, base=0):
        self.data = data
        self.base = base
        self.end = base + len(data)
        self.idx = 'prefix'
        self.version = '5.30'

    def off(self, va):
        return va - self.base

    def u32(self, va):
        return struct.unpack_from('<I', self.data, self.off(va))[0]

    def u64(self, va):
        return struct.unpack_from('<Q', self.data, self.off(va))[0]

    def cstr(self, va, limit=200):
        o = self.off(va)
        if not 0 <= o < len(self.data):
            return None
        raw = self.data[o:o + limit].split(b'\0', 1)[0]
        return raw.decode('latin1') if raw and all(32 <= c < 127 or c in (9, 10) for c in raw) else None

    def __repr__(self):
        return f'<Prefix 5.30 base={self.base:#x} size={len(self.data):#x}>'


_cache = {}


def prefix():
    if 'p' not in _cache:
        cache = HERE / 'prefix_5.30.bin'
        if cache.exists():
            data = cache.read_bytes()
        else:
            raw = DAT.read_bytes()
            data = raw.translate(bytes.maketrans(bytes(range(256)), bytes(255 - i for i in range(256))))[:PREFIX_END]
            cache.write_bytes(data)
        _cache['p'] = Prefix(data)
    return _cache['p']


# Boot-loader (raw-компонента DAT): file 0x60274 -> VA 0x40000.
# Подтверждено: заголовок @0x60274 (+0x08 = 0x40000 база, +0x10 = 0x1E340 размер),
# X-T5 4.31 streams.json (loader-00060274 address 262144=0x40000, raw),
# прологи резолвера 0x5460C/диспетчера 0x4A458/логгера 0x57670/скаляра 0x50D94.
LOADER_FILE = 0x60274
LOADER_BASE = 0x40000
LOADER_SIZE = 0x1E340


def loader():
    """Block-совместимый объект сервисного модуля (boot-loader), база 0x40000.
    dis/adrp_refs/bl_callers работают с реальными runtime VA."""
    if 'l' not in _cache:
        p = prefix()
        data = p.data[LOADER_FILE:LOADER_FILE + LOADER_SIZE]
        _cache['l'] = Prefix(data, base=LOADER_BASE)
    return _cache['l']
