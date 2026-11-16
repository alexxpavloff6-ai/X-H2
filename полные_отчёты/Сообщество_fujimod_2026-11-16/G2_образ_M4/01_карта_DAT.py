"""01: карта update.dat 5.33 — где лежат FFLZ-блоки и что остаётся «сырым».

Печатает и сохраняет `карта_DAT.json`: заголовки FFLZ (usize/csize), непокрытые
области, энтропия и первые строки. Только чтение.
"""
import hashlib
import json
import struct
import sys
from pathlib import Path

HERE = Path(__file__).resolve().parent
sys.path.insert(0, str(HERE))
import m4lib

fw = m4lib.load(m4lib.DAT_NEW)
dec, raw = fw['dec'], fw['raw']
n = len(raw)
res = {'file': fw['path'], 'size': n, 'size_hex': hex(n),
       'sha256_raw': hashlib.sha256(raw).hexdigest(),
       'version': '%x.%02x' % struct.unpack_from('<2I', raw, 0x204),
       'head_hex': raw[:0x40].hex(' '), 'dec_head_hex': dec[:0x40].hex(' ')}

blocks = m4lib.find_fflz(dec)
res['fflz'] = [{k: v for k, v in b.items() if k != 'data'} | {'off_hex': hex(b['off']),
                                                             'end_hex': hex(b['off'] + b['csize']),
                                                             'dec_sha256': hashlib.sha256(b['data']).hexdigest()}
               for b in blocks]
print('FFLZ blocks:')
for b in blocks:
    print(f"  off={b['off']:#x} csize={b['csize']:#x} usize={b['usize']:#x} pages={b['pages']} "
          f"page_size={b['page_size']:#x} align={b['align']:#x} ends={b['off']+b['csize']:#x}")

regions = m4lib.regions(n, blocks)
res['regions'] = []
print('regions:')
for s, e, name in regions:
    row = {'start': s, 'end': e, 'name': name, 'len': e - s,
           'start_hex': hex(s), 'end_hex': hex(e), 'len_hex': hex(e - s),
           'entropy_start': m4lib.entropy(dec, s, min(0x1000, e - s)),
           'entropy_mid': m4lib.entropy(dec, s + (e - s) // 2, min(0x1000, e - s)),
           'strings_start': m4lib.printable_runs(dec, s, min(0x2000, e - s), 10)[:12]}
    res['regions'].append(row)
    print(f"  {name:16s} {s:#010x}..{e:#010x} len={e-s:#x} H={row['entropy_start']}")

# что в самом начале файла (0..0x300274) — заголовок и загрузчик
res['prefix_strings'] = []
for off in range(0, 0x300274, 0x40000):
    ss = m4lib.printable_runs(dec, off, 0x40000, 12)
    if ss:
        res['prefix_strings'].append({'off': hex(off), 'strings': ss[:40]})
        print(f'--- prefix {off:#x}: {len(ss)} strings')
        for s in ss[:20]:
            print('   ', s)

(HERE / 'карта_DAT.json').write_text(json.dumps(res, ensure_ascii=False, indent=1), encoding='utf8')
print('saved карта_DAT.json')
