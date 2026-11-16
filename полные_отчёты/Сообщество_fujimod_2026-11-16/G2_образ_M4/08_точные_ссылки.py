"""08: (а) заголовок DAT 0..0x300 — есть ли таблица компонентов (TOC);
(б) точные ссылки на companion-SRAM/mailbox/reset-handshake с положительными контролями
    (MOVDC 0xFF970000, флаг 0x4c2ff14, задание 0x4daa6e8, release-константа 0xF0F0F0F0).

Все проверки ADRP — через fwcommon.adrp_sites/adrp_refs (только чтение).
"""
import json
import struct
import sys
from pathlib import Path

HERE = Path(__file__).resolve().parent
sys.path.insert(0, str(HERE))
import m4lib

sys.path.insert(0, str(m4lib.ANALYSIS / 'Сравнение_версий_2026-11-16'))
import fwcommon

fw = m4lib.load_dat(m4lib.DAT_NEW)
raw, dec = fw['raw'], fw['dec']
out = {}


class Buf:
    def __init__(self, data, base=0):
        self.data, self.base = data, base


blocks = [m4lib.load_block('X-H2', 'new', i) for i in range(4)]
prefix = Buf(dec[0:0x300274], 0)
tail = Buf(dec[0x284375c:], 0x284375c)

print('== заголовок DAT: dec 0..0x300')
for i in range(0, 0x300, 16):
    ch = dec[i:i + 16]
    print(f'  {i:04x}  {ch.hex(" "):<47}  ' + ''.join(chr(c) if 32 <= c < 127 else '.' for c in ch))
print('\n  raw 0..0x80:', raw[:0x80].hex(' '))
print('  u32 @0:', hex(struct.unpack_from('<I', raw, 0)[0]),
      ' @4:', hex(struct.unpack_from('<I', raw, 4)[0]),
      ' @0x204:', struct.unpack_from('<2I', raw, 0x204))
# ищем в заголовке пары (offset,size), похожие на описание компонентов
hdr = dec[:0x300]
pairs = []
for i in range(0, 0x300 - 8, 4):
    a, b = struct.unpack_from('<2I', hdr, i)
    if 0x1000 <= a < len(dec) and 0x1000 <= b < 0x8000000:
        pairs.append((i, hex(a), hex(b)))
print(f'  пар (offset,size)-подобных в 0..0x300: {len(pairs)}')
for p in pairs[:20]:
    print('   @%#x: %s %s' % p)
out['header'] = {'head_dec': dec[:0x300].hex(),
                 'pairs': [(hex(i), a, b) for i, a, b in pairs[:40]],
                 'version': struct.unpack_from('<2I', raw, 0x204)}

print('\n== точные ссылки: ADRP-страница + смещение (adrp_refs) и точные значения')
CASES = {
    'КОНТРОЛЬ MOVDC 0xFF970000': 0xFF970000,
    'КОНТРОЛЬ MOVDC-регистр 0xFF9700D8': 0xFF9700D8,
    'КОНТРОЛЬ флаг MOVDC 0x4c2ff14': 0x4C2FF14,
    'КОНТРОЛЬ задание 0x4daa6e8': 0x4DAA6E8,
    'companion-SRAM 0xFA200000': 0xFA200000,
    'companion-SRAM верх 0xFA300000': 0xFA300000,
    'mailbox 0xFF90E100': 0xFF90E100,
    'reset-handshake 0xFF91C000': 0xFF91C000,
    'reset-handshake триггер 0xFF91C00C': 0xFF91C00C,
    'boot-sram 0xFF800000': 0xFF800000,
    'GIC 0xFA000000': 0xFA000000,
}
refs = {}
for name, target in CASES.items():
    row = {'target': hex(target), 'per_buffer': {}}
    for bname, b in [('prefix', prefix)] + [(f'block{i}', blocks[i]) for i in range(3)]:
        sites = fwcommon.adrp_sites(b, target)
        hits = fwcommon.adrp_refs(b, target) if sites else []
        row['per_buffer'][bname] = {'adrp_pages': [hex(s) for s, _ in sites[:20]],
                                    'refs': [r['insn'] for r in hits[:10]]}
    print(f'  {name}:')
    for bname, v in row['per_buffer'].items():
        if v['adrp_pages'] or v['refs']:
            print(f"    {bname}: adrp={v['adrp_pages'][:4]} refs={v['refs'][:3]}")
    if not any(v['adrp_pages'] or v['refs'] for v in row['per_buffer'].values()):
        print('    нет ADRP-ссылок ни в префиксе, ни в блоках 0-2')
    refs[name] = row
out['exact_refs'] = refs

# точные 4/8-байтные значения по всем областям
print('\n== точные вхождения значений (без масок) по сырому DAT и блокам')
VALUES = {'FA200000': 0xFA200000, 'FA300000': 0xFA300000, 'FF90E100': 0xFF90E100,
          'FF91C000': 0xFF91C000, 'FF91C00C': 0xFF91C00C, 'FF970000': 0xFF970000,
          'F0F0F0F0': 0xF0F0F0F0}
exact = {}
for bname, buf in [('raw_all', dec[:len(dec) - 72])]:
    for vname, v in VALUES.items():
        p4 = struct.pack('<I', v)
        p8 = struct.pack('<Q', v)
        n4 = buf.count(p4)
        n8 = buf.count(p8)
        exact[f'{bname}:{vname}'] = {'u32': n4, 'u64': n8}
for i, b in enumerate(blocks):
    for vname, v in VALUES.items():
        exact[f'block{i}:{vname}'] = {'u32': b.data.count(struct.pack('<I', v)),
                                      'u64': b.data.count(struct.pack('<Q', v))}
for k, v in exact.items():
    if v['u32'] or v['u64']:
        print(f'  {k}: u32={v["u32"]} u64={v["u64"]}')
out['exact_values'] = exact

(HERE / 'точные_ссылки.json').write_text(json.dumps(out, ensure_ascii=False, indent=1), encoding='utf8')
print('saved точные_ссылки.json')
