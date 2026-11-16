"""F: общие помощники задачи F (мягкий cstr, ссылки на строки, границы функций)."""
import sys, re, struct
sys.path.insert(0, r'<корень проекта>\Анализ_прошивки\Сравнение_версий_2026-11-16')
from fwcommon import *
import fwcommon


def cstr2(b, va, limit=300):
    """C-строка, допускающая \\r и \\n (fwcommon.cstr их отбрасывает)."""
    o = b.off(va)
    if not 0 <= o < len(b.data):
        return None
    raw = b.data[o:o + limit].split(b'\0', 1)[0]
    if not raw:
        return None
    if all(32 <= c < 127 or c in (9, 10, 13) for c in raw):
        return raw.decode('latin1')
    return None


def adrp_add_all(b, lo, hi):
    """Все ADRP+ADD в диапазоне [lo,hi) -> [(site, target_va, string)]"""
    out = []
    for x in insns(b, lo, max(1, (hi - lo) // 4)):
        if x.mnemonic != 'adrp':
            continue
        page = int(x.op_str.split('#')[1], 0)
        reg = x.op_str.split(',')[0]
        for y in insns(b, x.address + 4, 3):
            m = re.fullmatch(r'(x\d+), (x\d+), #(-?0x[0-9a-f]+|-?\d+)', y.op_str)
            if y.mnemonic == 'add' and m and m.group(2) == reg:
                a = page + int(m.group(3), 0)
                out.append((x.address, a, cstr2(b, a)))
                break
    return out


def adrp_add_to(b, targets, win=3):
    """ADRP+ADD, точно попадающие в targets -> {target: [sites]}"""
    import collections
    res = collections.defaultdict(list)
    for va, w in iter_words(b):
        if (w & 0x9f000000) != 0x90000000:
            continue
        t = fwcommon._adrp_target(w, va)
        if not t:
            continue
        page, reg = t
        r = f'x{reg}'
        for y in insns(b, va + 4, win):
            m = re.fullmatch(r'(x\d+), (x\d+), #(-?0x[0-9a-f]+|-?\d+)', y.op_str)
            if y.mnemonic == 'add' and m and m.group(2) == r:
                a = page + int(m.group(3), 0)
                if a in targets:
                    res[a].append(y.address)
                break
    return res


def func_range(b, va, maxback=0x20000):
    """Грубые границы функции: назад до пролога, вперёд до следующего пролога."""
    fs = None
    o = b.off(va) & ~3
    for k in range(o, max(0, o - maxback), -4):
        w = struct.unpack_from('<I', b.data, k)[0]
        if (w & 0xffc07fff) == 0xa9807bfd:
            fs = b.base + k
            break
        if w == 0xd65f03c0 and k != o:
            fs = b.base + k + 4
            break
    if fs is None:
        fs = b.base + max(0, o - 0x200)
    fe = None
    for k in range(b.off(va) + 4, min(len(b.data) - 3, b.off(va) + 0x4000), 4):
        w = struct.unpack_from('<I', b.data, k)[0]
        if (w & 0xffc07fff) == 0xa9807bfd:
            fe = b.base + k
            break
    if fe is None:
        fe = b.base + min(len(b.data), b.off(va) + 0x4000)
    return fs, fe
