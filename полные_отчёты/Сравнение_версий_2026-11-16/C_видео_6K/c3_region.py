# -*- coding: utf-8 -*-
"""Шаг 3: линейный дамп региона модуля pm_dec/DEC_STA в текст + выборка
всех обращений к структуре состояния (в т.ч. через callee-saved регистры
после вызовов) и поиск инициализации буфера.

Запуск: python c3_region.py
Пишет:  c3_region_<model>_<state>.txt  (дизассемблирование 0x8e0000..0x920000)
        c3_state_wide.json           (все memop'ы с imm, у которых база ST
                                      установлена трассировкой регистров)
"""
import sys, os, json, re
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from c_common import *  # noqa

HERE = os.path.dirname(os.path.abspath(__file__))
REGION = {'X-H2': (0x8d0000, 0x920000), 'X-H2S': (0x8d0000, 0x920000),
          'X-T5': (0x870000, 0x8d0000)}

ANCH = {
    'X-H2':  {'old': (0x8fda98, 0x8fdc20, 0x8fdf68), 'new': (0x8fda98, 0x8fdcd8, 0x8fe0d8)},
    'X-H2S': {'old': (0x8f0d30, 0x8f0eb8, 0x8f1200), 'new': (0x8f0d30, 0x8f0f70, 0x8f1370)},
    'X-T5':  {'old': (0x8a2848, 0x8a29d0, 0x8a2d18), 'new': (0x8a2848, 0x8a2a88, 0x8a2e88)},
}

CALLS_SAVED = {'x19', 'x20', 'x21', 'x22', 'x23', 'x24', 'x25', 'x26', 'x27', 'x28'}


def trace(b, page, base, lo, hi):
    """Линейная трассировка: reg -> (страница, смещение) для ADRP(page)+ADD(base).

    Возвращает строки текста и список обращений к ST.
    """
    page = u64(page) & ~0xfff
    known = {}        # reg -> ('page',) | ('st',) | ('off', base)
    refs = []
    lines = []
    for x in insns(b, lo, (hi - lo) // 4):
        m, ops = x.mnemonic, [p.strip() for p in x.op_str.split(',')]
        if m == 'adrp':
            t = adrp_target64(b.u32(x.address), x.address)
            if t and ops:
                known[ops[0]] = ('page', t[0]) if (t[0] & ~0xfff) == page else None
                if known[ops[0]] is None:
                    known.pop(ops[0], None)
        elif m == 'add' and len(ops) == 3 and ops[0] == ops[1] and ops[2].startswith('#'):
            imm = int(ops[2].lstrip('#'), 0)
            if ops[0] in known and known[ops[0]] and known[ops[0]][0] == 'page':
                if imm == base:
                    known[ops[0]] = ('st',)
                elif imm < 0x1000:
                    known[ops[0]] = ('off', imm)
                else:
                    known.pop(ops[0], None)
        elif m in MEMOPS:
            hit = re.search(r'\[(x\d+)(?:, #(-?0x[0-9a-f]+|-?\d+))?\]', x.op_str)
            if hit and hit.group(1) in known:
                st = known[hit.group(1)]
                imm = int(hit.group(2), 0) if hit.group(2) else 0
                if st[0] == 'st':
                    refs.append({'site': x.address, 'rel': imm,
                                 'insn': f'{x.address:x}: {m} {x.op_str}',
                                 'kind': m})
                elif st[0] == 'off':
                    refs.append({'site': x.address, 'rel': st[1] + imm,
                                 'insn': f'{x.address:x}: {m} {x.op_str}',
                                 'kind': m})
                elif st[0] == 'page':
                    pass
            # загрузка в базовый регистр сбрасывает знание
            if m.startswith('ldr') and ops and ops[0] in known:
                known.pop(ops[0], None)
        elif m == 'mov' and len(ops) == 2 and ops[1] in known:
            known[ops[0]] = known[ops[1]]
        lines.append(f'{x.address:x}: {m} {x.op_str}')
    return lines, refs


def main():
    out = {}
    for mdl in MODELS:
        for st in ('old', 'new'):
            b = load(mdl, st, 2)
            page, base = find_state_base(b, ANCH[mdl][st][1])
            lo, hi = REGION[mdl]
            lines, refs = trace(b, page, base, lo, hi)
            open(os.path.join(HERE, f'c3_region_{mdl}_{st}.txt'), 'w', encoding='utf8').write(
                '\n'.join(lines) + '\n')
            out[f'{mdl} {st}'] = {'page': hex(page), 'base': hex(base),
                                  'refs': [{'site': hex(r['site']), 'rel': hex(r['rel']),
                                            'insn': r['insn']} for r in refs]}
            print(f'{mdl} {st}: page={page:#x} base={base:#x} refs={len(refs)}')
    open(os.path.join(HERE, 'c3_state_wide.json'), 'w', encoding='utf8').write(
        json.dumps(out, ensure_ascii=False, indent=1))


if __name__ == '__main__':
    main()
