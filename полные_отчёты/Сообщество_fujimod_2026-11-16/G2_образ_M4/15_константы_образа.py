"""15: полный линейный дизасм образа M4 (0x31A80 байт Thumb) + извлечение констант.

Собирает:
  * пары movw/movt (rX) → 32-битные константы (так в Thumb2 строят MMIO-адреса);
  * литералы `ldr rN,[pc,#imm]` → значение и куда указывает;
  * bl-цели (граф вызовов верхнего уровня);
  * все `str/ldr` с смещениями 0xD0/0xD8/0xF0/0x18 (MOVDC-подобные структуры).
Печатает окрестности использования «интересных» констант (0x5F90xxxx, 0xFA2xxxxx,
0xFF9xxxxx, 0x1003xxxx, 0x200000). Только чтение.
"""
import json
import re
import struct
import sys
from collections import Counter, defaultdict
from pathlib import Path

from capstone import Cs, CS_ARCH_ARM, CS_MODE_THUMB, CS_MODE_MCLASS

HERE = Path(__file__).resolve().parent
sys.path.insert(0, str(HERE))
import m4lib

IMG_OFF, IMG_LEN = 0x1C0274, 0x31A80
fw = m4lib.load_dat(m4lib.DAT_NEW)
img = fw['dec'][IMG_OFF:IMG_OFF + IMG_LEN]
cs = Cs(CS_ARCH_ARM, CS_MODE_THUMB | CS_MODE_MCLASS)
cs.detail = False

ins = list(cs.disasm(img, 0))
print(f'линейно дизассемблировано инструкций: {len(ins)} из {len(img)} байт')

# ---------------------------------------------------------- movw/movt → константы
movw = {}   # reg -> (imm, addr)
consts = []  # (value, addr, reg, 'movw|movt-pair')
for x in ins:
    m = x.mnemonic
    if m in ('movw', 'mov.w') and '#' in x.op_str:
        parts = [p.strip() for p in x.op_str.split(',')]
        if len(parts) == 2 and parts[1].startswith('#'):
            try:
                v = int(parts[1][1:], 0)
            except ValueError:
                continue
            if m == 'movw':
                movw[parts[0]] = (v, x.address)
    elif m == 'movt' and '#' in x.op_str:
        parts = [p.strip() for p in x.op_str.split(',')]
        if len(parts) == 2 and parts[0] in movw:
            lo, addr0 = movw[parts[0]]
            try:
                hi = int(parts[1][1:], 0)
            except ValueError:
                continue
            consts.append((hi << 16 | lo, addr0, parts[0], x.address))
print(f'пар movw/movt: {len(consts)}')

# ---------------------------------------------------------- литералы ldr [pc,#imm]
def literal_of(x):
    m = re.search(r'\[pc, #(0x[0-9a-f]+|\d+)\]', x.op_str)
    if not m:
        return None
    imm = int(m.group(1), 0)
    addr = (x.address + 4) & ~3
    tgt = addr + imm
    if 0 <= tgt <= len(img) - 4:
        return tgt, struct.unpack_from('<I', img, tgt)[0]
    return None


lits = []
for x in ins:
    if x.mnemonic.startswith('ldr'):
        r = literal_of(x)
        if r:
            lits.append((r[1], x.address, x.mnemonic + ' ' + x.op_str, r[0]))
print(f'литералов ldr [pc,#..]: {len(lits)}')

# ---------------------------------------------------------- интересные константы
def interesting(v):
    tags = []
    if 0x5F900000 <= v < 0x5FA00000:
        tags.append('5F9xxxxx-алиас периферии')
    if 0xFA200000 <= v < 0xFA300000:
        tags.append('companion-SRAM')
    if 0xFF900000 <= v < 0xFFA00000:
        tags.append('периферия 0xFF9x')
    if v in (0x10030001,) or 0x10030000 <= v < 0x10040000:
        tags.append('MOVDC-значение 0x1003xxxx')
    if v == 0x200000:
        tags.append('бит21')
    if 0x4C2F000 <= v < 0x4C30000:
        tags.append('флаг MOVDC A53')
    if 0x4DAA000 <= v < 0x4DAB000:
        tags.append('задание A53')
    return tags


rows = []
for v, addr, reg, addr2 in consts:
    tg = interesting(v)
    if tg:
        rows.append({'value': hex(v), 'movw_addr': hex(addr), 'movt_addr': hex(addr2), 'tags': tg})
for v, addr, text, lit_off in lits:
    tg = interesting(v)
    if tg:
        rows.append({'value': hex(v), 'insn_addr': hex(addr), 'text': text,
                     'literal_at': hex(lit_off), 'tags': tg})

print(f'\nинтересных констант: {len(rows)}')
by_tag = defaultdict(list)
for r in rows:
    for t in r['tags']:
        by_tag[t].append(r)
for t, rs in by_tag.items():
    print(f'  {t}: {len(rs)}')
    for r in rs[:12]:
        loc = r.get('movw_addr') or r.get('insn_addr')
        print(f'    {r["value"]:>10s} @ {loc}  ({r.get("text", "movw/movt")})')

# ---------------------------------------------------------- str/ldr с ключевыми смещениями
KEY_OFF = {0xD0: 'MOVDC stride', 0xD8: 'MOVDC рег mode', 0xF0: 'MOVDC +0xF0', 0x18: 'size +0x18'}
offs_hits = []
for x in ins:
    if x.mnemonic.startswith(('str', 'ldr')):
        m = re.search(r'\[(r\d+)(?:, #(0x[0-9a-f]+|\d+))?\]', x.op_str)
        if m and m.group(2):
            off = int(m.group(2), 0)
            if off in KEY_OFF:
                offs_hits.append((off, x.address, x.mnemonic + ' ' + x.op_str))
cnt = Counter(o for o, _, _ in offs_hits)
print(f'\nобращения с ключевыми смещениями: {dict(cnt)}')
for o, a, t in offs_hits[:25]:
    print(f'  +{o:#x} ({KEY_OFF[o]}): {a:#07x} {t}')

# ---------------------------------------------------------- bl-цели
targets = Counter()
bl_sites = []
for x in ins:
    if x.mnemonic.startswith('bl'):
        m = re.search(r'#(0x[0-9a-f]+|\d+)', x.op_str)
        if m:
            t = int(m.group(1), 0)
            targets[t] += 1
            bl_sites.append((x.address, t))
print(f'\nbl-вызовов: {len(bl_sites)}, уникальных целей: {len(targets)}')
print('  топ-15 целей:', [(hex(t), c) for t, c in targets.most_common(15)])

# ---------------------------------------------------------- строки
def good_strings(data, minlen=6):
    out = []
    for m in re.finditer(rb'[\x20-\x7e]{%d,}' % minlen, data):
        s = m.group().decode('latin1')
        letters = sum(c.isalpha() or c == ' ' for c in s)
        if letters >= 0.7 * len(s):
            out.append((m.start(), s))
    return out


gs = good_strings(img)
print(f'\n«человеческих» строк: {len(gs)}')
for off, s in gs[:60]:
    print(f'  +{off:#07x}  {s}')

out = {'constants': rows, 'key_offsets': [[hex(o), hex(a), t] for o, a, t in offs_hits],
       'bl_targets': [[hex(t), c] for t, c in targets.most_common(60)],
       'bl_count': len(bl_sites),
       'strings': [{'off': hex(o), 's': s} for o, s in gs],
       'insn_count': len(ins)}
(HERE / 'константы_образа.json').write_text(json.dumps(out, ensure_ascii=False, indent=1), encoding='utf8')
print('saved константы_образа.json')
