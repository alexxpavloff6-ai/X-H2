# -*- coding: utf-8 -*-
"""E43: кросс-модельная проверка RECF-поля режима:
- сколько обращений/записей к #0x3978 / #0x3eac / #0x3974 в блоке 1;
- какие ещё 32-битные поля RECF-контекста сравниваются с 0x2C и рядом читается счётчик [ctx+0x429c];
- контекст копий в H2S (0x33a073c) и поиск аналога в T5."""
import sys, re
sys.path.insert(0, r'<корень проекта>\Анализ_прошивки\Сравнение_версий_2026-11-16\E_сеттер_0x2B9')
from ecommon import *  # noqa

for model in ('X-H2', 'X-H2S', 'X-T5'):
    b = load(model, 'new', 1)
    print(f'\n##### {model} {b.version} (блок 1)')
    for off in (0x3978, 0x3eac, 0x3974):
        rows = [x for x in all_insns(b) if x.mnemonic != '.byte' and re.search(r'#0x%x\]' % off, x.op_str)]
        w = [x for x in rows if x.mnemonic.startswith('str')]
        print(f'  #0x{off:x}: всего {len(rows)}, записей {len(w)}: ' +
              ', '.join(f'{x.address:#x}' for x in w[:10]))
    # поля RECF-контекста, сравниваемые с 0x2c при чтении через [ctx+0x4000+...]
    print('  сравнения #0x2c, где рядом читается [x,#0x29c] (счётчик кадров):')
    ins = [x for x in all_insns(b) if x.mnemonic != '.byte']
    for i, x in enumerate(ins):
        if x.mnemonic == 'cmp' and re.match(r'w\d+, #0x2c$', x.op_str):
            win = ins[i:i + 20]
            cnt = [y for y in win if y.mnemonic == 'ldrh' and '#0x29c]' in y.op_str]
            if cnt:
                src = None
                for y in reversed(ins[max(0, i - 4):i]):
                    m = re.match(r'w(\d+), \[x(\d+), #(0x[0-9a-f]+)\]$', y.op_str)
                    if y.mnemonic == 'ldr' and m:
                        src = m.group(3)
                        break
                print(f'    cmp {x.address:#x}: {x.op_str}; поле {src}; счётчик {cnt[0].address:#x}')
