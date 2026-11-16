# -*- coding: utf-8 -*-
"""Мини-эмулятор линейного участка ARM64 для поиска обращений к глобальному адресу.

Экспорт:
    scan_address(model, state, block_idx, target, window=80) -> list[dict]
        {'site': hex(adrp), 'va': hex(insn), 'kind': 'r'|'w', 'stored': value|None,
         'insn': 'ldr w0, [x0, #0x43c]'}
    volatile: None (или список событий для всех адресов, если want_all=True)

Ограничения: линейный проход (ветвления не моделируются), значения трекаются
только для adrp/add/sub/mov/movz/movk; после bl регистры x0..x18 «забываются».
Это даёт кандидатов; каждый проверяется глазами по дизассемблеру.
"""
import sys, struct
sys.path.insert(0, r'<корень проекта>\Анализ_прошивки\Сравнение_версий_2026-11-16')
from fwcommon import *  # noqa
import fwcommon


def _adrp_sites_of_page(b, page):
    out = []
    data, base = b.data, b.base
    page &= ~0xfff
    for o in range(0, len(data) - 3, 4):
        w = struct.unpack_from('<I', data, o)[0]
        if (w & 0x9f000000) == 0x90000000:
            t = fwcommon._adrp_target(w, base + o)
            if t and t[0] == page:
                out.append((base + o, t[1]))
    return out


def _parse_mem(ins):
    op = ins.op_str
    if '[' not in op:
        return None
    pre, mem = op.split('[', 1)
    mem, post = mem.split(']', 1)
    parts = [p.strip() for p in mem.split(',')]
    rn = parts[0]
    off = 0
    if len(parts) > 1 and parts[1].startswith('#'):
        try:
            off = int(parts[1][1:].split(',')[0], 0)
        except ValueError:
            off = None
    else:
        off = None
    if len(parts) > 2 and parts[2].startswith('#'):
        try:
            off = (off or 0) + int(parts[2][1:], 0)
        except ValueError:
            off = None
    regs = [p.strip() for p in pre.split(',')]
    rt = regs[0] if regs else ''
    return rn, off, rt


def _norm(r):
    r = r.strip()
    if r.startswith('w') and r[1:].isdigit():
        return 'x' + r[1:]
    return r


def emulate(b, start, maxn=80, init=None, want=None):
    """Вернуть события памяти [(va, addr, kind, stored, text)] на линейном участке.

    init: {reg: value} — начальные значения (например, база структуры).
    want: (lo, hi) — если задано, события вне диапазона отбрасываются.
    """
    val = dict(init or {})
    events = []
    for ins in insns(b, start, maxn):
        va = ins.address
        m = ins.mnemonic
        ops = [p.strip() for p in ins.op_str.split(',')]
        if m[:3] in ('ldr', 'str', 'ldp', 'stp', 'ldur', 'stur'):
            if m.startswith('ldp') or m.startswith('stp'):
                rn, off, rt = _parse_mem(ins)
                if rn in val and val[rn] is not None and off is not None:
                    events.append((va, val[rn] + off,
                                   'w' if m.startswith('stp') else 'r', None,
                                   f'{m} {ins.op_str}'))
                for p in ops[:2]:
                    val[_norm(p)] = None
                continue
            rn, off, rt = _parse_mem(ins)
            if rn in val and val[rn] is not None and off is not None:
                kind = 'w' if m.startswith('str') else 'r'
                store_val = None
                if kind == 'w':
                    s = _norm(rt)
                    if rt in ('wzr', 'xzr'):
                        store_val = 0
                    elif s in val:
                        store_val = val[s]
                events.append((va, val[rn] + off, kind, store_val, f'{m} {ins.op_str}'))
            if not m.startswith('str'):
                val[_norm(rt)] = None
            continue
        if m == 'adrp':
            val[_norm(ops[0])] = int(ops[1].split('#')[1], 0)
            continue
        if m in ('add', 'sub'):
            rd, rn = _norm(ops[0]), _norm(ops[1])
            if len(ops) == 3:
                src = ops[2]
                if src.startswith('#'):
                    try:
                        imm = int(src[1:].split(',')[0], 0)
                    except ValueError:
                        val[rd] = None
                        continue
                    if ', lsl #12' in ops[2]:
                        imm <<= 12
                    base = val.get(rn)
                    val[rd] = None if base is None else base + (imm if m == 'add' else -imm)
                else:
                    a, c = val.get(rn), val.get(_norm(src))
                    val[rd] = (a + c) if (a is not None and c is not None and m == 'add') else None
            continue
        if m == 'mov' and len(ops) == 2:
            val[_norm(ops[0])] = val.get(_norm(ops[1]))
            continue
        if m in ('movz', 'movn'):
            try:
                imm = int(ops[1].split('#')[1], 0)
                if ', lsl #' in ops[1]:
                    imm <<= int(ops[1].split(', lsl #')[1], 0)
                val[_norm(ops[0])] = imm if m == 'movz' else (~imm) & ((1 << 64) - 1)
            except (ValueError, IndexError):
                val[_norm(ops[0])] = None
            continue
        if m == 'movk':
            rd = _norm(ops[0])
            try:
                imm = int(ops[1].split('#')[1], 0)
                sh = int(ops[1].split(', lsl #')[1], 0) if ', lsl #' in ops[1] else 0
                cur = val.get(rd)
                if cur is None:
                    val[rd] = None
                else:
                    val[rd] = (cur & ~(0xffff << sh)) | (imm << sh)
            except (ValueError, IndexError):
                val[rd] = None
            continue
        if m in ('bl', 'blr'):
            for r in ['x%d' % i for i in range(19)]:
                val[r] = None
            continue
        if m == 'ret':
            break
        if m == 'b':
            break
    return events


def scan_address(model, state, block_idx, target, window=80):
    b = load(model, state, block_idx)
    sites = _adrp_sites_of_page(b, target & ~0xfff)
    rows = []
    for va, reg in sites:
        for (iva, a, kind, sv, txt) in emulate(b, va, window):
            if a == target:
                rows.append({'site': hex(va), 'va': hex(iva), 'kind': kind,
                             'stored': sv, 'insn': txt})
    seen, uniq = set(), []
    for r in rows:
        k = (r['va'], r['kind'])
        if k in seen:
            continue
        seen.add(k)
        uniq.append(r)
    return uniq


if __name__ == '__main__':
    import json
    for m, st, tgt in [('X-H2', 'new', 0x4c2ff14)]:
        for r in scan_address(m, st, 1, tgt):
            print(r)
