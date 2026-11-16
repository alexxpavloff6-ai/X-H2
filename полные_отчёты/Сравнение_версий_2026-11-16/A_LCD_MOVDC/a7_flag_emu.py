# -*- coding: utf-8 -*-
"""Шаг 7: линейный «мини-эмулятор» для поиска ВСЕХ обращений (r/w) к глобальному
флагу MOVDC, включая adrp+add+str с большим расстоянием между add и str.

Идея: стартуем со всех ADRP на страницу флага, ведём значения регистров
(adrp/add/mov/sub/movz/movk), фиксируем ldr/str/ldrb/strb/stp/ldp по известным
адресам, останавливаемся на ret/безусловном b, после bl забываем x0..x18.

Печатает: модель состояние | адрес инструкции | адрес памяти | r/w | значение (если известно).
"""
import sys, os, json, struct
sys.path.insert(0, r'<корень проекта>\Анализ_прошивки\Сравнение_версий_2026-11-16')
from fwcommon import *  # noqa
import fwcommon

HERE = os.path.dirname(os.path.abspath(__file__))
FLAG = {
    ('X-H2', 'old'): (0x4c33f14, 0x43c),
    ('X-H2', 'new'): (0x4c2ff14, 0x43c),
    ('X-H2S', 'old'): (0x4ba8f0c, 0x434),
    ('X-H2S', 'new'): (0x4ba8f0c, 0x434),
    ('X-T5', 'old'): (0x4ab72c4, 0x43c),
    ('X-T5', 'new'): (0x4ab72c4, 0x43c),
}
WINDOW = 80


def adrp_sites_of_page(b, page):
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


def parse_mem(ins):
    """('x0','w0','#0x10', write?) -> (base_reg, off, rt) или None."""
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


def norm(r):
    r = r.strip()
    if r.startswith('w') and r[1:].isdigit():
        return 'x' + r[1:]
    return r


def emulate(b, start, page, flag, foff, maxn=WINDOW):
    """Вернуть список событий [(va, addr, kind, value, insn_text)]."""
    val = {}
    events = []
    for i, ins in enumerate(insns(b, start, maxn)):
        va = ins.address
        m = ins.mnemonic
        ops = [p.strip() for p in ins.op_str.split(',')]
        # -------- memory access --------
        if m[:3] in ('ldr', 'str', 'ldp', 'stp', 'ldur', 'stur'):
            # обрабатываем только одиночные ldr/str/ldrb/strb/strh/ldrh/ldrsb/ldrsw
            if m.startswith('ldp') or m.startswith('stp'):
                rn, off, rt = parse_mem(ins)
                if rn in val and val[rn] is not None and off is not None:
                    a = val[rn] + off
                    kind = 'w' if m.startswith('stp') else 'r'
                    events.append((va, a, kind, None, f'{m} {ins.op_str}'))
                # ldp/stp пишут регистры
                for p in ops[:2]:
                    val[norm(p)] = None
                continue
            rn, off, rt = parse_mem(ins)
            if rn in val and val[rn] is not None and off is not None:
                a = val[rn] + off
                kind = 'w' if m.startswith('str') else 'r'
                store_val = None
                if kind == 'w':
                    s = norm(rt)
                    if rt in ('wzr', 'xzr'):
                        store_val = 0
                    elif s in val:
                        store_val = val[s]
                events.append((va, a, kind, store_val, f'{m} {ins.op_str}'))
            if not m.startswith('str'):
                val[norm(rt)] = None
            continue
        # -------- adrp/add/sub/mov --------
        if m == 'adrp':
            rd = norm(ops[0])
            val[rd] = int(ops[1].split('#')[1], 0)
            continue
        if m in ('add', 'sub'):
            rd, rn = norm(ops[0]), norm(ops[1])
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
                    if base is not None:
                        val[rd] = base + (imm if m == 'add' else -imm)
                    else:
                        val[rd] = None
                else:
                    a, c = val.get(rn), val.get(norm(src))
                    val[rd] = (a + c) if (a is not None and c is not None and m == 'add') else None
            continue
        if m == 'mov' and len(ops) == 2:
            val[norm(ops[0])] = val.get(norm(ops[1]))
            continue
        if m in ('movz', 'movn'):
            try:
                imm = int(ops[1].split('#')[1], 0)
                if ', lsl #' in ops[1]:
                    imm <<= int(ops[1].split(', lsl #')[1], 0)
                val[norm(ops[0])] = imm if m == 'movz' else (~imm) & ((1 << 64) - 1)
            except (ValueError, IndexError):
                val[norm(ops[0])] = None
            continue
        if m == 'movk':
            rd = norm(ops[0])
            try:
                imm = int(ops[1].split('#')[1], 0)
                sh = int(ops[1].split(', lsl #')[1], 0) if ', lsl #' in ops[1] else 0
                cur = val.get(rd)
                if cur is None:
                    val[rd] = None
                else:
                    mask = ~(0xffff << sh)
                    val[rd] = (cur & mask) | (imm << sh)
            except (ValueError, IndexError):
                val[rd] = None
            continue
        if m == 'bl' or m == 'blr':
            for r in ['x0', 'x1', 'x2', 'x3', 'x4', 'x5', 'x6', 'x7', 'x8',
                      'x9', 'x10', 'x11', 'x12', 'x13', 'x14', 'x15', 'x16', 'x17', 'x18']:
                val[r] = None
            continue
        if m in ('ret',):
            break
        if m == 'b':
            # если это хвостовой переход внутри функции — дальше значения не наши
            break
        if m.startswith('b.') or m in ('cbz', 'cbnz', 'tbz', 'tbnz'):
            continue
        if m in ('ldrsw', 'ldrb', 'ldrh'):
            val[norm(ins.op_str.split(',')[0])] = None
            continue
    return events


def main():
    out = {}
    for m in MODELS:
        for st in ('old', 'new'):
            b = load(m, st, 1)
            flag, foff = FLAG[(m, st)]
            page = flag & ~0xfff
            sites = adrp_sites_of_page(b, page)
            rows = []
            for va, reg in sites:
                ev = emulate(b, va, page, flag, foff)
                for (iva, a, kind, sv, txt) in ev:
                    if a == flag:
                        rows.append({'adrp': hex(va), 'va': hex(iva), 'kind': kind,
                                     'stored': sv, 'insn': txt})
            # дедуп по (va,kind)
            seen = set()
            uniq = []
            for r in rows:
                k = (r['va'], r['kind'])
                if k in seen:
                    continue
                seen.add(k)
                uniq.append(r)
            print(f'=== {m} {st}: flag={flag:#x} adrp-sites={len(sites)} accesses={len(uniq)}')
            for r in uniq:
                print(f"  {r['va']:>10} {r['kind']} stored={r['stored']}  {r['insn']}   (adrp {r['adrp']})")
            out[f'{m} {st}'] = uniq
    open(os.path.join(HERE, 'flag_access_emu.json'), 'w', encoding='utf8').write(
        json.dumps(out, ensure_ascii=False, indent=1))


if __name__ == '__main__':
    main()
