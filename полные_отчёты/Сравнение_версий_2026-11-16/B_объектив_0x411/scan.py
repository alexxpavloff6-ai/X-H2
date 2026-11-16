"""Сканер констант в ARM64-блоках прошивки (только чтение).

Ищет:
  * cmp/sub/add с непосредственным imm12;
  * movz/movk (в т.ч. составные 32-битные константы);
  * tbnz/tbz по номеру бита;
  * литеральные halfword/word в data-секциях.

Кэш результатов — в этой же папке (*.json).
"""
import json
import struct
import sys
from pathlib import Path

HERE = Path(__file__).resolve().parent
sys.path.insert(0, str(HERE.parent))
from fwcommon import load, MODELS  # noqa: E402

CACHE = HERE / 'cache'


def words(b):
    """(va, word) по всем выровненным словам."""
    data = b.data
    base = b.base
    for o in range(0, len(data) - 3, 4):
        yield base + o, struct.unpack_from('<I', data, o)[0]


def find_imm12(b, value, ops=(0x71, 0x11, 0x51, 0x31)):
    """cmp/cmn/add/sub (imm12) с заданным значением. ops — старшие байты (sf=0/1)."""
    out = []
    for va, w in words(b):
        top = w >> 24
        if top not in ops:
            continue
        if (w >> 22) & 1:  # sh=1 -> imm<<12
            continue
        imm = (w >> 10) & 0xfff
        if imm == value:
            out.append(va)
    return out


def find_movz_w(b, value):
    out = []
    for va, w in words(b):
        if (w & 0x7f800000) == 0x52800000:
            if ((w >> 5) & 0xffff) == (value & 0xffff) and ((w >> 21) & 3) == 0:
                out.append(va)
    return out


def find_movk_w(b, value):
    out = []
    for va, w in words(b):
        if (w & 0x7f800000) == 0x72800000:
            if ((w >> 5) & 0xffff) == (value & 0xffff) and ((w >> 21) & 3) in (0, 1):
                out.append(va)
    return out


def find_movz_x(b, value):
    out = []
    for va, w in words(b):
        if (w & 0x7f800000) == 0xd2800000:
            if ((w >> 5) & 0xffff) == (value & 0xffff) and ((w >> 21) & 3) in (0, 1):
                out.append(va)
    return out


def find_tbz(b, bit):
    out = []
    for va, w in words(b):
        if (w & 0x7f000000) in (0x36000000, 0x37000000):
            if ((w >> 19) & 0x1f) == bit:
                out.append(va)
    return out


def find_literal_u16(b, value, span):
    """Литеральные halfword в диапазоне [0, span) файла."""
    needle = struct.pack('<H', value)
    data = b.data
    out = []
    i = data.find(needle)
    while 0 <= i < span:
        out.append(b.base + i)
        i = data.find(needle, i + 1)
    return out


def find_compound(b, value):
    """movz w,#lo + movk w,#hi,lsl#16 в пределах 4 инструкций (тот же rd)."""
    out = []
    ws = list(words(b))
    for k, (va, w) in enumerate(ws):
        if (w & 0x7f800000) != 0x52800000:
            continue
        lo = (w >> 5) & 0xffff
        hw = (w >> 21) & 3
        rd = w & 0x1f
        cur = lo << (16 * hw)
        for va2, w2 in ws[k + 1:k + 5]:
            if (w2 & 0x7f800000) == 0x72800000 and (w2 & 0x1f) == rd:
                cur |= ((w2 >> 5) & 0xffff) << (16 * ((w2 >> 21) & 3))
        if cur == value:
            out.append(va)
    return out


def scan_all(model, state, idx, what, value, span=None):
    b = load(model, state, idx)
    res = {'cmp12': find_imm12(b, value),
           'movz': find_movz_w(b, value),
           'movzk': find_compound(b, value)}
    if span:
        res['lit_u16'] = find_literal_u16(b, value, span)
    return res


if __name__ == '__main__':
    # самопроверка: известная точка cmp w21,#0x411 в X-H2 new
    b = load('X-H2', 'new', 1)
    cmp411 = find_imm12(b, 0x411)
    print('X-H2 new cmp #0x411:', [hex(x) for x in cmp411])
    print('  0x2dec9b0 в списке:', 0x2dec9b0 in cmp411)
    print('X-H2 new cmp #0x411 count:', len(cmp411))
