"""X-H2 5.30: UI color -> artificial parameter -> output word, execute original ARM64.
Does not establish real UI-to-frame or output-to-file execution; no source is modified.
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
from capstone import Cs, CS_ARCH_ARM64, CS_MODE_LITTLE_ENDIAN

spec = importlib.util.spec_from_file_location('prior', ANALYSIS / 'Рецепты/Цветовые_этапы_31.10.2026/проверить_цветовые_этапы.py')
prior = importlib.util.module_from_spec(spec)
spec.loader.exec_module(prior)
source = prior.base.SOURCE

def sha(path):
    return hashlib.sha256(path.read_bytes()).hexdigest()

before = sha(source)
x = prior.Study()
params, out = 0x60000000, 0x60020000

def execute(gate, mode, color):
    x.clear(params, 0x8000)
    x.clear(out, 0x1000)
    x.word(params + 0x3978, gate)
    x.word(params + 0x39b8, mode)
    x.word(params + 0x39b4, color)
    x.uc.mem_write(out + 0x9a, b'\x5a\xa5')
    x.run(0x2e552a4, until=0x2e552b0, registers={19: params, 20: out})
    return struct.unpack('<H', x.uc.mem_read(out + 0x9a, 2))[0]

rows = []
for ui in range(9):
    x.word(0x2051408, 0)
    representation = x.run(0x12e67ac, [0x6b3, ui, 0, 3])
    error = x.u32(0x2051408)
    sign_value = struct.unpack_from('<i', x.a, 0x176d7b0 - 0x1101000 + ui * 16 + 12)[0]
    result = execute(2, 19, representation)
    rows.append({'ui_index': ui, 'table_fourth_field_tenths': sign_value,
                 'mode_representation_3': representation, 'converter_error': error,
                 'output_0x9a': result, 'output_0x9a_hex': f'0x{result:04x}'})
expected = [0xe0, 0xc0, 0x100, 0x80, 0, 0x180, 0x400, 0x4c0, 0x4e0]
assert [r['output_0x9a'] for r in rows] == expected
controls = []
for gate, mode, color in ((2, 19, 3), (2, 19, 4), (2, 19, 2), (2, 4, 3),
                          (46, 19, 3), (2, 19, 9), (45, 19, 3)):
    value = execute(gate, mode, color)
    controls.append({'gate': gate, 'mode': mode, 'color': color, 'output': value})
assert [c['output'] for c in controls] == [0x80, 0, 0x100, 0x300, 0xffff, 0, 0x80]

md = Cs(CS_ARCH_ARM64, CS_MODE_LITTLE_ENDIAN)
base = 0x29ae000
asm = []
for start, end in ((0x2e552a4, 0x2e552b0), (0x2e51064, 0x2e51324)):
    asm.append(f'# original ARM64 {start:#x}..{end:#x} (virtual addresses)')
    for ins in md.disasm(x.b[start-base:end-base], start):
        asm.append(f'{ins.address:08x} {ins.bytes.hex()} {ins.mnemonic} {ins.op_str}')

metadata_file = HERE.parent / 'Байты_MakerNote/байты.json'
metadata = json.loads(metadata_file.read_text(encoding='utf-8'))
actual = {r['file']: r['tags']['Saturation']['value'] for r in metadata['files']
          if r['file'] in ('DSCF0300.JPG', 'DSCF0301.JPG', 'DSCF0302.JPG')}
assert actual == {'DSCF0300.JPG': 0x80, 'DSCF0301.JPG': 0, 'DSCF0302.JPG': 0x100}
after = sha(source)
assert before == after
result = {'source_sha256_before': before, 'source_sha256_after': after,
          'method': 'UI converter run separately; researcher writes output to artificial params+0x39b4 and artificial mode/gate; caller 0x2e552a4 invokes 0x2e51064 and stores output+0x9a. JPEG comparison is external correlation, not actual camera execution or proof of serializer.',
          'input_mode': 19, 'input_gate': 2, 'rows': rows, 'negative_controls': controls,
          'camera_jpeg_tag_0x1003': actual,
          'metadata_source': str(metadata_file.relative_to(ANALYSIS))}
(HERE / 'результат.json').write_text(json.dumps(result, ensure_ascii=False, indent=2) + '\n', encoding='utf-8')
(HERE / 'инструкции.asm').write_text('\n'.join(asm) + '\n', encoding='utf-8')
print(json.dumps({'source_unchanged': before == after, 'rows': rows, 'controls': controls, 'jpeg_tags': actual}, ensure_ascii=False, indent=2))
