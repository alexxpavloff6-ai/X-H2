"""16: корректный линейный свип Thumb по образу M4 (с ресинхронизацией на 2 байта),
дампа кода вокруг MOVDC-подобных записей (+0xD0/+0xD8/+0xF0), литералов 0x5F9x/0xFA2x/0xFF9x
и 0x274-байтного заголовка перед образом (flash 0x1C0000).

Только чтение.
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
dec = fw['dec']
img = dec[IMG_OFF:IMG_OFF + IMG_LEN]
cs = Cs(CS_ARCH_ARM, CS_MODE_THUMB | CS_MODE_MCLASS)


def sweep(data, start=0):
    """Линейный свип Thumb: при сбое декодера пропускаем 2 байта и продолжаем."""
    out = []
    off = start
    n = len(data)
    while off < n - 1:
        got = 0
        for x in cs.disasm(data[off:off + 16], off):
            out.append(x)
            off += x.size
            got += 1
            break
        if not got:
            off += 2
    return out


ins = sweep(img)
print(f'свип: инструкций {len(ins)}, покрыто {sum(x.size for x in ins)} байт из {len(img)}')
addr_set = {x.address for x in ins}


def dump(lo, hi, tag='', limit=200):
    print(f'--- {tag} [{lo:#x}..{hi:#x})  DAT {IMG_OFF + lo:#x}')
    n = 0
    for x in ins:
        if lo <= x.address < hi:
            print(f'  {x.address:06x}  {x.bytes.hex():<10} {x.mnemonic:<8} {x.op_str}')
            n += 1
            if n >= limit:
                break


# ---------------------------------------------------------- заголовок перед образом
print('\n== 0x274 байта перед образом (flash 0x1C0000..0x1C0274)')
hdr = dec[0x1C0000:0x1C0274]
for i in range(0, len(hdr), 16):
    ch = hdr[i:i + 16]
    print(f'  {0x1C0000 + i:08x}  {ch.hex(" "):<47}  ' +
          ''.join(chr(c) if 32 <= c < 127 else '.' for c in ch))
print('  u32:', [hex(v) for v in struct.unpack_from('<8I', hdr, 0)])
print('  u32 @0x100:', [hex(v) for v in struct.unpack_from('<8I', hdr, 0x100)])

# ---------------------------------------------------------- MOVDC-подобные записи
print('\n== код вокруг записей +0xD0/+0xD8/+0xF0')
dump(0x0BF0, 0x0D00, 'MOVDC-инициализация')
dump(0x1300, 0x1400, 'второй сайт +0xD0/+0xF0')

# ---------------------------------------------------------- литералы
def literal_va(x):
    m = re.search(r'\[pc, #(0x[0-9a-f]+|\d+)\]', x.op_str)
    if not m:
        return None
    tgt = ((x.address + 4) & ~3) + int(m.group(1), 0)
    if 0 <= tgt <= len(img) - 4:
        return tgt, struct.unpack_from('<I', img, tgt)[0]
    return None


lits = []
for x in ins:
    if x.mnemonic.startswith('ldr'):
        r = literal_va(x)
        if r:
            lits.append({'insn': x.address, 'text': f'{x.mnemonic} {x.op_str}',
                         'lit_off': r[0], 'value': r[1]})
print(f'\nлитералов: {len(lits)}')

def cat(v):
    if 0x5F900000 <= v < 0x5FA00000:
        return 'алиас 0x5F9x'
    if 0xFA200000 <= v < 0xFA400000:
        return 'SRAM 0xFA2x/0xFA3x'
    if 0xFF900000 <= v < 0xFFA00000:
        return 'периферия 0xFF9x'
    if 0x10000000 <= v < 0x10100000:
        return 'константа 0x100xxxxx'
    if 0x200000 == v:
        return 'бит 21'
    if 0xF0000000 <= v < 0xF8000000:
        return 'flash-апертура'
    return None


groups = defaultdict(list)
for r in lits:
    c = cat(r['value'])
    if c:
        groups[c].append(r)
for c, rs in groups.items():
    print(f'  {c}: {len(rs)}')
    for r in rs:
        print(f"    insn {r['insn']:06x}  {r['text']:<32} -> {r['value']:#010x} (литерал @{r['lit_off']:#x})")

# для каждой такой ссылки — контекст
print('\n== контекст использования интересных литералов (по 10 инструкций вокруг)')
CTX = {'алиас 0x5F9x', 'периферия 0xFF9x', 'SRAM 0xFA2x/0xFA3x', 'константа 0x100xxxxx'}
for c in CTX:
    for r in groups.get(c, [])[:12]:
        a = r['insn']
        lo, hi = max(0, a - 24), a + 24
        dump(lo, hi, f'{c} = {r["value"]:#x} (insn {a:#x})', limit=20)

out = {'insn_count': len(ins), 'literals': lits,
       'groups': {c: rs for c, rs in groups.items()},
       'words_in_5F97': [hex(i * 4) for i in range(len(img) // 4)
                         if 0x5F970000 <= struct.unpack_from('<I', img, i * 4)[0] < 0x5F974000],
       'hdr_u32': [hex(v) for v in struct.unpack_from('<16I', dec, 0x1C0000)]}
(HERE / 'свип_образа.json').write_text(json.dumps(out, ensure_ascii=False, indent=1), encoding='utf8')
print('saved свип_образа.json')
