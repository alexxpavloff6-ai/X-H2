"""F: таблица «смещение поля настроек -> имя» из большого логгера бэкапа (b0).

Логгер (диапазон ~0x1264000..0x1269000, X-H2 5.33 b0) на каждое поле делает
ldrb/ldr [settings+off] -> печатает format "$BACKUP[%d]<имя> %s(%d)->%s(%d)".
Собираем пары (off, имя), беря ближайшую ПОСЛЕ места чтения format-строку.
"""
import sys, re, json, struct, collections
sys.path.insert(0, '<корень проекта>/Анализ_прошивки/Сравнение_версий_2026-11-16/F_режим_съёмки')
from fhelp import *

b = load('X-H2', 'new', 0)
LO, HI = 0x1264000, 0x1269000

xs = list(insns(b, LO, (HI - LO) // 4))
# 1) индексы format-строк "$BACKUP..." и их адреса
fmt_sites = []
i = 0
while i < len(xs):
    x = xs[i]
    if x.mnemonic == 'adrp':
        page = int(x.op_str.split('#')[1], 0)
        reg = x.op_str.split(',')[0]
        for y in xs[i + 1:i + 4]:
            m = re.fullmatch(r'(x\d+), (x\d+), #(-?0x[0-9a-f]+|-?\d+)', y.op_str)
            if y.mnemonic == 'add' and m and m.group(2) == reg:
                s = cstr2(b, page + int(m.group(3), 0))
                if s and '$BACKUP' in s:
                    fmt_sites.append((x.address, s))
                break
    i += 1
print(f'format-строк BACKUP: {len(fmt_sites)}')

# 2) чтения полей: ldrb w?, [x?, #off] (off < 0x2000)
reads = []
for x in xs:
    if x.mnemonic == 'ldrb' or (x.mnemonic == 'ldr' and x.op_str.startswith('w')):
        m = re.fullmatch(r'w\d+, \[x\d+, #(0x[0-9a-f]+|\d+)\]', x.op_str)
        if m and int(m.group(1), 0) < 0x2000:
            reads.append((x.address, int(m.group(1), 0)))
print(f'чтений полей: {len(reads)}')

# 3) для каждого чтения — ближайшая format-строка после него в пределах 0x60 байт
pairs = []
for a, off in reads:
    cand = [(fa, s) for fa, s in fmt_sites if a <= fa <= a + 0x80]
    if cand:
        pairs.append((off, cand[0][0], cand[0][1]))
seen = {}
for off, fa, s in pairs:
    name = re.sub(r'^.*\[\%d\]', '', s).split(' %s')[0]
    seen.setdefault(off, set()).add(name)
print('\n-- off -> имена --')
for off in sorted(seen):
    print(f'  {off:#06x}: {sorted(seen[off])}')

json.dump({f'{k:#x}': sorted(v) for k, v in seen.items()}, open('settings_field_names.json', 'w'),
          indent=1, ensure_ascii=False)
for want in (0x144, 0x1da, 0x5a0, 0x59f):
    print(f'offset {want:#x}: {sorted(seen.get(want, []))}')
