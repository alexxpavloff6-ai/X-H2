# -*- coding: utf-8 -*-
"""Q3 шаг 19: функции, читающие через get-API (0x12E67AC/0x1135930/0x11335EC)
свойства сценария; ищем одновременное чтение SHUTTER_TYPE+CONTINUOUS+REC_VIEW."""
import json
import sys
from pathlib import Path

HERE = Path(__file__).resolve().parent
sys.path.insert(0, str(HERE))
from q3common import load, insns, bl_callers, func_start, dis  # noqa: E402

IDS = {0xB: 'REC_VIEW', 0x827: 'SHUTTER_TYPE', 0x858: 'CONTINUOUS',
       0xAAB: 'SPEED_OUTPUT', 0xAB8: 'SHUTTERTYPE_OUTPUT', 0x8A0: 'SPEED_M',
       0x89E: 'SHUTTER_SPEED', 0xAC7: 'DOTLCD_SHUTTERTYPE', 0xACE: 'DOTLCD_CONTINUOUS'}
GET_APIS = (0x12E67AC, 0x1135930, 0x11335EC, 0x12D6BC8)

byfunc = {}
for idx in (0, 1):
    b = load('X-H2', 'old', idx)
    for api in GET_APIS:
        for site, k in bl_callers(b, api):
            # w0 = id обычно загружен в preceding 6 инструкций
            idval = None
            for ins in insns(b, site - 0x18, 7):
                if ins.mnemonic in ('mov', 'movz') and ins.op_str.startswith('w0, #'):
                    try:
                        idval = int(ins.op_str.split('#')[1], 0)
                    except ValueError:
                        pass
            if idval in IDS:
                fs = func_start(b, site)
                key = (idx, fs)
                byfunc.setdefault(key, set()).add(IDS[idval])

# функции с >=3 факторами, исключая generic-хелпер 0x113D9E0
cands = []
for (idx, fs), names in byfunc.items():
    if fs in (0x113D9E0, None):
        continue
    if len(names) >= 3:
        cands.append({'block': idx, 'func': hex(fs), 'factors': sorted(names), 'n': len(names)})
cands.sort(key=lambda c: -c['n'])
result = {'multi_factor_functions': cands,
          'all_functions': [{'block': i, 'func': hex(f) if f else None, 'factors': sorted(n)}
                            for (i, f), n in byfunc.items()]}
(HERE / 'условие_дефекта_кандидаты.json').write_text(json.dumps(result, ensure_ascii=False, indent=2) + '\n', encoding='utf-8')
print('функции с >=3 факторами (кроме generic-хелпера):')
for c in cands:
    print(' ', c)
# дизасм лучшего кандидата
if cands:
    top = cands[0]
    b = load('X-H2', 'old', top['block'])
    txt = dis(b, int(top['func'], 16), 120)
    (HERE / 'лучший_кандидат.txt').write_text(txt + '\n', encoding='utf-8')
    print('\n=== лучший кандидат', top['func'], '===')
    print(txt[:5000])
