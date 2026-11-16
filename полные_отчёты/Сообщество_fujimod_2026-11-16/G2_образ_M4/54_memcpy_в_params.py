"""54: кто заполняет pending-параметры 0x4C3B090 (и, значит, поле +0x74 = 0x4C3B104).

Ищем в блоке 1 (new 5.33) все вызовы memcpy 0x1533EBC и смотрим аргументы x0 (dst), x1 (src), w2 (n),
разрешая adrp+add в пределах предыдущих 8 инструкций. Отдельно — вызовы, у которых dst внутри
pending/current params. Плюс полный дизасм функции 0x3101504..0x31015B4.

Только чтение.
"""
import json
import re
import sys
from pathlib import Path

HERE = Path(__file__).resolve().parent
sys.path.insert(0, str(HERE))
import m4lib

sys.path.insert(0, str(m4lib.ANALYSIS / 'Сравнение_версий_2026-11-16'))
import fwcommon

MEMCPY = 0x1533EBC
lines = []
out = []
b = fwcommon.load('X-H2', 'new', 1)


def emit(s=''):
    print(s)
    lines.append(s)


emit('== полный дизасм 0x3101504..0x31015B4 (заполнение pending/current)')
for x in fwcommon.insns(b, 0x3101504, (0x31015B4 - 0x3101504) // 4):
    emit(f'  {x.address:08x}  {x.bytes.hex():<10} {x.mnemonic:<8} {x.op_str}')

emit('\n== вызовы memcpy 0x1533EBC: аргументы (dst/src/n)')
calls = fwcommon.bl_callers(b, MEMCPY)
emit(f'  всего вызовов: {len(calls)}')
for site, kind in calls:
    seq = fwcommon.insns(b, site - 0x24, 10)
    regs = {}
    page = None
    for x in seq:
        m = re.search(r'adrp\s+(x\d+), #(0x[0-9a-f]+)', f'{x.mnemonic} {x.op_str}')
        if m:
            page = (m.group(1), int(m.group(2), 0))
            continue
        m = re.search(r'add\s+(x\d+), (x\d+), #(0x[0-9a-f]+)', f'{x.mnemonic} {x.op_str}')
        if m and page and m.group(2) == page[0]:
            regs[m.group(1)] = page[1] + int(m.group(3), 0)
            continue
        m = re.search(r'mov\s+(w\d+), #(0x[0-9a-f]+)', f'{x.mnemonic} {x.op_str}')
        if m:
            regs[m.group(1)] = int(m.group(2), 0)
    dst = regs.get('x0')
    src = regs.get('x1')
    n = regs.get('w2') or regs.get('x2')
    interesting = dst is not None and (0x4C3B000 <= dst < 0x4C3B400 or 0x4C3F000 <= dst < 0x4C3F400
                                       or 0x4C2F000 <= dst < 0x4C30000)
    emit(f'  {site:08x}  dst={dst if dst is None else hex(dst)} src={src if src is None else hex(src)} '
         f'n={n if n is None else hex(n)}' + ('  <== интересно' if interesting else ''))
    if interesting:
        out.append({'site': hex(site), 'dst': hex(dst), 'src': hex(src) if src else None,
                    'n': hex(n) if n else None})
        for x in seq[-6:]:
            emit(f'      {x.address:08x}  {x.mnemonic:<8} {x.op_str}')

(HERE / 'memcpy_в_params.txt').write_text('\n'.join(lines) + '\n', encoding='utf8')
(HERE / 'memcpy_в_params.json').write_text(json.dumps(out, ensure_ascii=False, indent=1), encoding='utf8')
print('saved memcpy_в_params.txt/.json')
