"""36: для каждого ADRP на страницу таблицы (0x385E000 new / 0x3862000 old) печатаем
следующие 6 инструкций — ищем, кто читает записи 0x...170..0x...240 (MOVDC-карта).

Только чтение.
"""
import json
import sys
from pathlib import Path

HERE = Path(__file__).resolve().parent
sys.path.insert(0, str(HERE))
import m4lib

sys.path.insert(0, str(m4lib.ANALYSIS / 'Сравнение_версий_2026-11-16'))
import fwcommon

lines = []
out = {}


def emit(s=''):
    print(s)
    lines.append(s)


for state, page in (('old', 0x3862000), ('new', 0x385E000)):
    b = fwcommon.load('X-H2', state, 1)
    sites = fwcommon.adrp_sites(b, page)
    emit(f'== X-H2 {b.version} ADRP на {page:#x}: {len(sites)}')
    seen = {}
    for s, r in sites:
        seq = fwcommon.insns(b, s, 6)
        txt = [f'{x.mnemonic} {x.op_str}' for x in seq]
        emit(f'  {s:08x} x{r}: ' + ' | '.join(txt))
        # какие иммедиаты после adrp упоминаются
        for x in seq[1:]:
            if x.mnemonic in ('add', 'ldr', 'str', 'ldrb', 'strb', 'ldrh', 'strh', 'orr'):
                import re
                m = re.search(r'#(0x[0-9a-f]+|\d+)', x.op_str)
                if m:
                    imm = int(m.group(1), 0)
                    if 0x100 <= imm < 0x300:
                        seen.setdefault(imm, []).append(hex(s))
    emit(f'  иммедиаты 0x100..0x300 в продолжениях: '
         + ', '.join(f'{k:#x}:{len(v)}' for k, v in sorted(seen.items())))
    out[state] = {'sites': [hex(s) for s, _ in sites], 'imm_hits': {hex(k): v for k, v in seen.items()}}

(HERE / 'adrp_продолжения.txt').write_text('\n'.join(lines) + '\n', encoding='utf8')
(HERE / 'adrp_продолжения.json').write_text(json.dumps(out, ensure_ascii=False, indent=1), encoding='utf8')
print('saved adrp_продолжения.txt/.json')
