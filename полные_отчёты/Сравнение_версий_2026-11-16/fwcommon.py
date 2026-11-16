"""Shared read-only helpers for the old/new firmware diff workers.

Blocks were decoded once by распаковать_блоки.py into blocks/*.bin.
Usage (run from any directory):
    import sys; sys.path.insert(0, r'<корень проекта>\\Анализ_прошивки\\Сравнение_версий_2026-11-16')
    from fwcommon import *
    b = load('X-H2', 'new', 1)          # second block (high-level ARM64 code)
    print(dis(b, 0x3103ff8, 40))       # disassemble by runtime VA
    print(adrp_refs(b, 0x4c2ff14))     # ADRP(+ADD)+LDR/STR references to an absolute address
"""
from pathlib import Path
import json, re, struct, sys

HERE = Path(__file__).resolve().parent
sys.path.insert(0, str(HERE.parent / 'инструменты'))
from capstone import Cs, CS_ARCH_ARM64, CS_MODE_LITTLE_ENDIAN  # noqa: E402

INDEX = json.loads((HERE / 'blocks' / 'index.json').read_text(encoding='utf8'))
MODELS = ('X-H2', 'X-H2S', 'X-T5')
# Block numbers: 0 = first FFLZ, 1 = second (high-level ARM64, base at +8),
# 2 = low-level ARM64 (base 0, addresses are file offsets), 3 = Linux/other (unchanged).
cs = Cs(CS_ARCH_ARM64, CS_MODE_LITTLE_ENDIAN)
cs.detail = False
_cache = {}


class Block:
    def __init__(self, model, state, idx):
        row = INDEX[f'{model} {state}']['blocks'][idx]
        self.model, self.state, self.idx = model, state, idx
        self.version = INDEX[f'{model} {state}']['version']
        self.data = (HERE / row['file']).read_bytes()
        base = struct.unpack_from('<Q', self.data, 8)[0]
        self.base = base if idx in (0, 1) else 0
        self.end = self.base + len(self.data)

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
        return f'<Block {self.model} {self.version} b{self.idx} base={self.base:#x} size={len(self.data):#x}>'


def load(model, state, idx):
    key = (model, state, idx)
    if key not in _cache:
        _cache[key] = Block(model, state, idx)
    return _cache[key]


def dis(b, va, count=30):
    o = b.off(va)
    lines = []
    for i in cs.disasm(b.data[o:o + count * 4], va):
        lines.append(f'{i.address:x}: {i.mnemonic} {i.op_str}')
        if len(lines) >= count:
            break
    return '\n'.join(lines)


def insns(b, va, count):
    o = b.off(va)
    return list(cs.disasm(b.data[o:o + count * 4], va))[:count]


def iter_words(b):
    """Yield (va, word) for every aligned 32-bit word of the block."""
    data, base = b.data, b.base
    for o in range(0, len(data) - 3, 4):
        yield base + o, struct.unpack_from('<I', data, o)[0]


def _adrp_target(word, pc):
    if (word & 0x9f000000) != 0x90000000:
        return None
    immlo = (word >> 29) & 3
    immhi = (word >> 5) & 0x7ffff
    imm = (immhi << 2) | immlo
    if imm & (1 << 20):
        imm -= 1 << 21
    return (pc & ~0xfff) + (imm << 12), word & 31


def adrp_sites(b, page):
    """All ADRP instructions that load the 4 KiB page `page` -> list of (va, reg)."""
    page &= ~0xfff
    out = []
    data, base = b.data, b.base
    for o in range(0, len(data) - 3, 4):
        w = struct.unpack_from('<I', data, o)[0]
        if (w & 0x9f000000) == 0x90000000:
            t = _adrp_target(w, base + o)
            if t and t[0] == page:
                out.append((base + o, t[1]))
    return out


def adrp_refs(b, target, window=12):
    """Resolve ADRP [+ADD] then LDR/STR/ADD uses that hit absolute `target`.

    Returns rows {'site', 'insn'}; covers both `ldr w0,[x0,#lo]` and `add x0,x0,#lo` forms.
    """
    rows = []
    for va, reg in adrp_sites(b, target):
        r = f'x{reg}'
        addr = target & ~0xfff
        for x in insns(b, va + 4, window):
            ops = [p.strip() for p in x.op_str.split(',')]
            m = re.search(r'#(-?0x[0-9a-f]+|-?\d+)', x.op_str)
            imm = int(m.group(1), 0) if m else 0
            if x.mnemonic == 'add' and len(ops) >= 3 and ops[1] == r:
                if addr + imm == target:
                    rows.append({'site': x.address, 'insn': f'{x.address:x}: {x.mnemonic} {x.op_str}'})
                if ops[0] == r:
                    addr += imm
                    continue
                break
            if x.mnemonic[:3] in ('ldr', 'str', 'stp', 'ldp') and f'[{r}' in x.op_str:
                if addr + imm == target:
                    rows.append({'site': x.address, 'insn': f'{x.address:x}: {x.mnemonic} {x.op_str}'})
                if ops[0] in (r, 'w' + r[1:]):
                    break
                continue
            if x.mnemonic in ('bl', 'b', 'ret', 'br', 'blr'):
                break
    return rows


def bl_callers(b, target):
    """Direct BL/B call sites to `target`."""
    out = []
    data, base = b.data, b.base
    for o in range(0, len(data) - 3, 4):
        w = struct.unpack_from('<I', data, o)[0]
        if (w & 0x7c000000) == 0x14000000:
            imm = w & 0x3ffffff
            if imm & (1 << 25):
                imm -= 1 << 26
            if base + o + imm * 4 == target:
                out.append((base + o, 'bl' if w & 0x80000000 else 'b'))
    return out


def find_bytes(b, needle):
    out, start = [], 0
    while True:
        i = b.data.find(needle, start)
        if i < 0:
            return out
        out.append(b.base + i)
        start = i + 1


def func_start(b, va, limit=0x4000):
    """Walk back to the nearest `stp x29, x30, [sp, #-N]!` style prologue or preceding ret."""
    o = b.off(va) & ~3
    for k in range(o, max(0, o - limit), -4):
        w = struct.unpack_from('<I', b.data, k)[0]
        if (w & 0xffc07fff) == 0xa9807bfd:  # stp x29, x30, [sp, #imm]!
            return b.base + k
        if w == 0xd65f03c0 and k != o:  # ret
            return b.base + k + 4
    return None


def string_refs(b, va_from, va_to):
    """C strings referenced by ADRP+ADD pairs inside [va_from, va_to)."""
    out = []
    for x in insns(b, va_from, (va_to - va_from) // 4):
        if x.mnemonic == 'adrp':
            page = int(x.op_str.split('#')[1], 0)
            reg = x.op_str.split(',')[0]
            for y in insns(b, x.address + 4, 4):
                if y.mnemonic == 'add' and y.op_str.startswith(f'{reg}, {reg}, #'):
                    a = page + int(y.op_str.split('#')[1], 0)
                    s = b.cstr(a)
                    if s:
                        out.append((x.address, hex(a), s))
                    break
    return out
