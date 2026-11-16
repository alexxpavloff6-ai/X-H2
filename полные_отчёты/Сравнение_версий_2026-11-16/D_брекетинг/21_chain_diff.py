# -*- coding: utf-8 -*-
"""D: доказательство, что в функции подготовки кадра изменение ровно одно —
вставка 9 инструкций, и других правок в ней нет (для всех трёх моделей).

Метод: инструкции old и new нормализуются (цели ветвлений -> смещение от начала
функции, adrp-страницы -> <pg>, прочие крупные иммедиаты -> <A>), затем difflib
сравнивает последовательности. Вставка = единственный блок `insert`.
"""
import sys, re, json
sys.path.insert(0, r'<корень проекта>\Анализ_прошивки\Сравнение_версий_2026-11-16\D_брекетинг')
from dhelp import *  # noqa
import difflib

STARTS = {
    ('X-H2', 'old'): 0x2cecf2c, ('X-H2', 'new'): 0x2ce8f3c,
    ('X-H2S', 'old'): 0x30049e4, ('X-H2S', 'new'): 0x30049f4,
    ('X-T5', 'old'): 0x2c2bbf0, ('X-T5', 'new'): 0x2c2bc1c,
}
END_OFF = 0x10f4      # длина функции в new (проверено: ret в start+0x10F4)

def instr_text(b, start, end):
    out = []
    for x in all_insns(b, start, end):
        if x.mnemonic == '.byte':
            continue
        ops = x.op_str
        m = re.match(r'#0x([0-9a-f]+)$', ops)
        if m and (x.mnemonic.startswith('b') or x.mnemonic in ('cbz', 'cbnz', 'tbz', 'tbnz')):
            out.append((x.address, f'{x.mnemonic} @{int(m.group(1),16)-start:+#x}'))
            continue
        ops = re.sub(r'#0x([0-9a-f]+)', lambda mm: '#0x%x' % int(mm.group(1), 16)
                     if int(mm.group(1), 16) < 0x1000 else '<A>', ops)
        out.append((x.address, f'{x.mnemonic} {ops}'))
    return out

report = {}
for m in MODELS:
    o = instr_text(load(m, 'old', 1), STARTS[(m, 'old')], STARTS[(m, 'old')] + END_OFF + 0x40)
    n = instr_text(load(m, 'new', 1), STARTS[(m, 'new')], STARTS[(m, 'new')] + END_OFF)
    so = [t for _, t in o]
    sn = [t for _, t in n]
    sm = difflib.SequenceMatcher(None, so, sn, autojunk=False)
    hunks = []
    for tag, i1, i2, j1, j2 in sm.get_opcodes():
        if tag == 'equal':
            continue
        hunks.append({'tag': tag, 'old_i': [i1, i2], 'new_i': [j1, j2],
                      'old_addr': hex(o[i1][0]) if i1 < len(o) else None,
                      'new_addr': hex(n[j1][0]) if j1 < len(n) else None,
                      'old': [so[k] for k in range(i1, min(i2, i1 + 14))],
                      'new': [sn[k] for k in range(j1, min(j2, j1 + 14))]})
    report[m] = {'old_start': hex(STARTS[(m, 'old')]), 'new_start': hex(STARTS[(m, 'new')]),
                 'old_instr': len(so), 'new_instr': len(sn), 'hunks': hunks}
    print(f'=== {m}: old {len(so)} инстр., new {len(sn)} инстр., различий-блоков {len(hunks)}')
    for h in hunks:
        print(f'  {h["tag"]}: old[{h["old_i"][0]}:{h["old_i"][1]}] @ {h["old_addr"]} -> '
              f'new[{h["new_i"][0]}:{h["new_i"][1]}] @ {h["new_addr"]}')
        for s in h['old']:
            print('    -', s)
        for s in h['new']:
            print('    +', s)

json.dump(report, open('chain_diff.json', 'w', encoding='utf8'), ensure_ascii=False, indent=1)
print('\nсохранено chain_diff.json')
