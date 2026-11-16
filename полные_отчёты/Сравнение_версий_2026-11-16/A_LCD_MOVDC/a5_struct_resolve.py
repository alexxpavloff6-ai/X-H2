# -*- coding: utf-8 -*-
"""Шаг 5: для каждого LDR/STR с offset 0x434/0x43c/0x2c4 восстановить базу
(ищем назад add xN,xN,#imm и adrp xN,page) и оставить только «настоящие»
обращения к глобальным структурам (база 0x4900000..0x4d00000).

Печатает строки: model state hit_va target(=base+off) insn.
"""
import sys, os, json
sys.path.insert(0, r'<корень проекта>\Анализ_прошивки\Сравнение_версий_2026-11-16')
from fwcommon import *  # noqa
import struct

HERE = os.path.dirname(os.path.abspath(__file__))
OFFS = [0x434, 0x43c, 0x2c4]
LO, HI = 0x4900000, 0x4d00000


def find_ls_off(b, byte_off):
    out = []
    data, base = b.data, b.base
    for o in range(0, len(data) - 3, 4):
        w = struct.unpack_from('<I', data, o)[0]
        if (w & 0x3b000000) != 0x39000000:
            continue
        size = w >> 30
        if (((w >> 10) & 0xfff) << size) == byte_off:
            out.append((base + o, w))
    return out


def resolve_base(b, va):
    """Вернуть (target, adrp_va, add_va) для ldr/str в va или None."""
    x = insns(b, va, 1)
    if not x:
        return None
    ins = x[0]
    ops = [p.strip() for p in ins.op_str.split(',')]
    mem = [p for p in ops if p.startswith('[')]
    if not mem:
        return None
    rn = mem[0][1:].split(',')[0].split(']')[0]
    # walk back
    cur = va
    base = None
    add_va = None
    for k in range(1, 10):
        prev = insns(b, cur - 4 * k, 1)
        if not prev:
            break
        p = prev[0]
        if p.mnemonic == 'add' and p.op_str.startswith(f'{rn}, {rn}, #'):
            try:
                imm = int(p.op_str.split('#')[1].split(',')[0], 0)
            except ValueError:
                break
            if ', lsl' in p.op_str:
                break
            add_va = p.address
            # find adrp for rn
            for j in range(1, 6):
                q = insns(b, add_va - 4 * j, 1)
                if not q:
                    break
                qq = q[0]
                if qq.mnemonic == 'adrp' and qq.op_str.startswith(f'{rn}, #'):
                    page = int(qq.op_str.split('#')[1], 0)
                    base = page + imm
                    break
            break
        if p.mnemonic == 'adrp' and p.op_str.startswith(f'{rn}, #'):
            base = int(p.op_str.split('#')[1], 0)
            break
        if p.mnemonic in ('ret', 'bl', 'b'):
            break
    if base is None:
        return None
    off = 0
    for tok in mem[0].strip('[]').split(','):
        tok = tok.strip()
        if tok.startswith('#'):
            off = int(tok[1:], 0)
    return base + off, add_va


def main():
    rows = []
    for m in MODELS:
        for st in ('old', 'new'):
            b = load(m, st, 1)
            for off in OFFS:
                for va, w in find_ls_off(b, off):
                    r = resolve_base(b, va)
                    if not r:
                        continue
                    tgt, add_va = r
                    if not (LO <= tgt < HI):
                        continue
                    ins = insns(b, va, 1)[0]
                    rows.append((m, st, va, tgt, ins, add_va))
    for m, st, va, tgt, ins, add_va in rows:
        a = f'add@{add_va:#x}' if add_va else 'no-add'
        print(f'{m:5s} {st} {va:#010x} -> {tgt:#010x} {a}  {ins.mnemonic} {ins.op_str}')
    print('total', len(rows))
    open(os.path.join(HERE, 'struct_targets.txt'), 'w', encoding='utf8').write(
        '\n'.join(f'{m} {st} {va:#x} {tgt:#x} {ins.mnemonic} {ins.op_str}' for m, st, va, tgt, ins, _ in rows))


if __name__ == '__main__':
    main()
