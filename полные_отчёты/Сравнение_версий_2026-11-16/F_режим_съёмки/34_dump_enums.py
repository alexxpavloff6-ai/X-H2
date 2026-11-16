"""F: выгрузка найденных enum-таблиц (значение -> строковое имя) в enums.txt.

Таблицы:
  1) MODE_RECORD_*  — резолвер 0x1141ee0 (b0 X-H2 5.33), домен 0..~0x60;
  2) MODE_CONTINUOUS_* — резолвер 0x11427a8, домен 0..0xe;
  3) BKUP_DOTLCD_POWOFF_DRIVEMODE_* — резолвер 0x116bcc8, домен 0..0x1a.
"""
import sys, re
sys.path.insert(0, '<корень проекта>/Анализ_прошивки/Сравнение_версий_2026-11-16/F_режим_съёмки')
from fhelp import *


def block_string(b, target):
    xs = insns(b, target, 4)
    if not xs or xs[0].mnemonic != 'adrp':
        return None
    page = int(xs[0].op_str.split('#')[1], 0)
    reg = xs[0].op_str.split(',')[0]
    if len(xs) > 1 and xs[1].mnemonic == 'add':
        m = re.fullmatch(r'(x\d+), (x\d+), #(-?0x[0-9a-f]+|-?\d+)', xs[1].op_str)
        if m and m.group(2) == reg:
            return cstr2(b, page + int(m.group(3), 0))
    return None


def decode(b, entry, maxn=600, stop_at=0x1142818):
    out = {}
    for x in insns(b, entry, maxn):
        s = x.op_str
        m = re.fullmatch(r'w\d+, #(-?0x[0-9a-f]+|-?\d+)', s)
        if x.mnemonic == 'cbz':
            t = int(s.split('#')[1], 0)
            out[0] = block_string(b, t)
            continue
        if m and x.mnemonic == 'cmp':
            v = int(m.group(1), 0)
            nxt = insns(b, x.address + 4, 1)
            if nxt and nxt[0].mnemonic == 'b.eq':
                t = int(nxt[0].op_str.split('#')[1], 0)
                out[v] = block_string(b, t)
            continue
        if x.mnemonic == 'csel':
            prev = insns(b, x.address - 4, 1)
            if prev and prev[0].mnemonic == 'cmp':
                v = int(re.search(r'#(-?0x[0-9a-f]+|-?\d+)', prev[0].op_str).group(1), 0)
                out[v] = 'LAST_CANDIDATE'
            break
        if x.address >= stop_at and len(out) > 0x30:
            break
    return out


b = load('X-H2', 'new', 0)
blocks = {
    'MODE_RECORD (0x1141ee0)': (0x1141ee0, 0x700),
    'MODE_CONTINUOUS (0x11427a8)': (0x11427a8, 0x80),
    'DRIVEMODE_BKUP (0x116bcc8)': (0x116bcc8, 0x80),
}
with open('enums.txt', 'w', encoding='utf8') as f:
    for name, (entry, n) in blocks.items():
        d = decode(b, entry, n)
        f.write(f'== {name}: {len(d)} значений\n')
        for k in sorted(d):
            f.write(f'   {k:#04x}  {d[k]}\n')
        f.write('\n')
        print(name, len(d))
print('written enums.txt')
