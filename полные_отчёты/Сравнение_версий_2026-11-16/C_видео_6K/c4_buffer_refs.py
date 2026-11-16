# -*- coding: utf-8 -*-
"""Шаг 4: кто читает/пишет таблицу указателей буферов (0x9cb060..0x9cb0d8)
и где инициализируется указатель записи ST+0x38.

Запуск: python c4_buffer_refs.py
"""
import sys, os, json, re
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from c_common import *  # noqa

HERE = os.path.dirname(os.path.abspath(__file__))
PAGE = 0x9cb000


def refs_page(b, page, lo_imm=0, hi_imm=0x100):
    out = []
    for va, reg in adrp_sites64(b, page):
        r = f'x{reg}'
        cur = 0
        for x in insns(b, va + 4, 8):
            ops = [p.strip() for p in x.op_str.split(',')]
            if x.mnemonic == 'add' and len(ops) == 3 and ops[0] == r and ops[1] == r:
                cur += int(ops[2].lstrip('#'), 0)
                continue
            if x.mnemonic in ('ldr', 'ldrb', 'ldrh', 'ldrsb', 'str', 'strb') and f'[{r}' in x.op_str:
                m = re.search(r'#(-?0x[0-9a-f]+|-?\d+)', x.op_str)
                imm = cur + (int(m.group(1), 0) if m else 0)
                if lo_imm <= imm <= hi_imm:
                    out.append({'site': x.address, 'imm': imm,
                                'insn': f'{x.address:x}: {x.mnemonic} {x.op_str}',
                                'target': u64(page + imm)})
                break
            if x.mnemonic in ('bl', 'b', 'ret', 'br', 'blr', 'adrp', 'mov', 'madd'):
                break
    return out


def main():
    allrefs = {}
    for m in MODELS:
        for st in ('old', 'new'):
            b = load(m, st, 2)
            rows = refs_page(b, PAGE, 0x50, 0x100)
            allrefs[f'{m} {st}'] = [{'site': hex(r['site']), 'target': hex(r['target']),
                                     'insn': r['insn']} for r in rows]
            if m == 'X-H2':
                print(f'=== {m} {st}')
                for r in rows:
                    val = None
                    if r['insn'].split()[1].startswith('ldr'):
                        pass
                    print(f"   {r['insn']}   -> {r['target']:#x}  "
                          f"{b.u64(r['target']):#x} {b.cstr(r['target'], 40)!r}")
    open(os.path.join(HERE, 'c4_buffer_refs.json'), 'w', encoding='utf8').write(
        json.dumps(allrefs, ensure_ascii=False, indent=1))


if __name__ == '__main__':
    main()
