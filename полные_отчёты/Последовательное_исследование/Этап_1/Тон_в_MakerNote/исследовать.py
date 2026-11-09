"""X-H2 highlight/shadow UI conversion, metadata writers and Fuji directory builder.
Manually joined with artificial memory; not a complete camera execution.
"""
from pathlib import Path
import hashlib
import importlib.util
import json
import struct
import sys

HERE = Path(__file__).resolve().parent
ANALYSIS = HERE.parents[2]
sys.path.insert(0, str(ANALYSIS / 'инструменты'))
spec = importlib.util.spec_from_file_location('prior', ANALYSIS / 'Рецепты/Цветовые_этапы_31.10.2026/проверить_цветовые_этапы.py')
prior = importlib.util.module_from_spec(spec)
spec.loader.exec_module(prior)
source = prior.base.SOURCE

def sha(path):
    return hashlib.sha256(path.read_bytes()).hexdigest()

before = sha(source)
x = prior.Study()
for addr in (0x260c000, 0x2430000, 0x229b000, 0x2055000, 0x253a000):
    x.uc.mem_map(addr, 0x1000)
params, obj, buf = 0x60000000, 0x60010000, 0x60020000
rows = []
for shadow_ui, highlight_ui in ((7, 5), (8, 8), (8, 5), (7, 8)):
    x.clear(params, 0x8000)
    x.clear(obj, 0x10000)
    x.clear(buf, 0x10000)
    for addr in (0x260c000, 0x2430000, 0x229b000, 0x2055000, 0x253a000):
        x.clear(addr)
    x.word(0x2051408, 0)
    shadow = x.run(0x12e67ac, [0x6bb, shadow_ui, 0, 3])
    shadow_error = x.u32(0x2051408)
    x.word(0x2051408, 0)
    highlight = x.run(0x12e67ac, [0x6b9, highlight_ui, 0, 3])
    highlight_error = x.u32(0x2051408)
    x.word(params + 0x3978, 2)
    x.word(params + 0x3a90, shadow)
    x.word(params + 0x3a8c, highlight)
    x.run(0x2e4f7bc, [params, obj])
    x.run(0x2e4f90c, [params, obj])
    s, h = struct.unpack('<i', x.uc.mem_read(obj + 0x124, 4))[0], struct.unpack('<i', x.uc.mem_read(obj + 0x128, 4))[0]
    predicates = [x.run(0x134df8c, [2, tag, obj]) for tag in (0x1040, 0x1041)]
    length = x.run(0x13503e4, [2, obj, buf, buf])
    directory = bytes(x.uc.mem_read(buf, length))
    records = {}
    for tag in (0x1040, 0x1041):
        prefix = struct.pack('<HHI', tag, 9, 1)
        positions = [i for i in range(len(directory)-11) if directory[i:i+8] == prefix]
        if len(positions) != 1:
            raise RuntimeError(f'Tag {tag:#x}: {positions}')
        records[f'0x{tag:04x}'] = directory[positions[0]:positions[0]+12].hex(' ')
    rows.append({'ui_shadow': shadow_ui, 'ui_highlight': highlight_ui,
                 'input_shadow': shadow, 'input_highlight': highlight,
                 'ui_errors': [shadow_error, highlight_error], 'metadata_shadow': s,
                 'metadata_highlight': h, 'predicates': predicates, 'records': records})
assert [(r['metadata_shadow'], r['metadata_highlight']) for r in rows] == [(-8, -24), (0, 0), (0, -24), (-8, 0)]
assert all(r['ui_errors'] == [0, 0] and r['predicates'] == [1, 1] for r in rows)
metadata = json.loads((HERE.parent / 'Байты_MakerNote/байты.json').read_text(encoding='utf-8'))
photo = next(r for r in metadata['files'] if r['file'] == 'DSCF0300.JPG')
for tag, name in (('0x1040', 'ShadowTone'), ('0x1041', 'HighlightTone')):
    assert rows[0]['records'][tag].replace(' ', '') == photo['tags'][name]['ifd_entry_hex']
after = sha(source)
assert before == after
result = {'source_sha256_before': before, 'source_sha256_after': after,
          'method': 'Separate original UI converters, researcher writes outputs and gate 2 to artificial params. Original two metadata functions populate shared synthetic object. Builder independently receives same object from researcher. No real camera execution or complete UI-to-file path shown.',
          'parameters': {'shadow_input_offset': '0x3a90', 'highlight_input_offset': '0x3a8c',
                         'shadow_writer': '0x2e4f7bc', 'highlight_writer': '0x2e4f90c',
                         'shadow_object_offset': '0x124', 'highlight_object_offset': '0x128'},
          'cases': rows, 'photo_comparison': 'DSCF0300.JPG exact 12-byte IFD entries; metadata is not proof of original camera execution'}
(HERE / 'результаты.json').write_text(json.dumps(result, ensure_ascii=False, indent=2) + '\n', encoding='utf-8')
print(json.dumps(rows, ensure_ascii=False, indent=2))
