"""Execute model-specific film-to-color/selector/calculator with synthetic inputs.
Stage boundaries are joined by the researcher. Does not render pixels or run cameras.
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
spec = importlib.util.spec_from_file_location('calc', ANALYSIS / 'Единый_глубокий_анализ/сопоставить_цветовые_расчёты.py')
calc = importlib.util.module_from_spec(spec)
spec.loader.exec_module(calc)
tables = calc.tables
from unicorn import Uc, UC_ARCH_ARM64, UC_MODE_ARM

MODE_FUNCTION_OFFSET = {'X-H2': 0x58ac30, 'X-H2S': 0x5859a8,
                        'X-T5': 0x588f2c, 'X100VI': 0x5bfee4}
MODE_LABELS = {13: 'CLASSIC_CHROME', 19: 'SUPERIA', 22: 'REALA'}
result = {}
for name, (selector, calculate, pointer) in calc.CONFIG.items():
    rel, expected, ao, bo, _, _, template, _ = tables.FILES[name]
    path = ANALYSIS.parent / rel
    raw = path.read_bytes()
    before = hashlib.sha256(raw).hexdigest()
    assert before == expected
    decoded = raw.translate(tables.base.TRANSLATION)
    a, b = tables.base.unpack_fflz(decoded, ao), tables.base.unpack_fflz(decoded, bo)
    base_a, base_b = struct.unpack_from('<Q', a, 8)[0], struct.unpack_from('<Q', b, 8)[0]
    uc = Uc(UC_ARCH_ARM64, UC_MODE_ARM)
    uc.mem_map(base_a, 0x6000000 - base_a)
    uc.mem_write(base_a, a)
    uc.mem_write(base_b, b)
    uc.mem_map(0x27008000, 0x100000)
    uc.mem_write(0x27008000, decoded[template:template+0xc6c00])
    uc.mem_write(pointer, struct.pack('<Q', 0x27008000))
    uc.mem_map(0x60000000, 0x20000)
    uc.mem_map(0x70000000, 0x10000)
    src, out = 0x60000000, 0x60010000
    modes = []
    for mode, label in MODE_LABELS.items():
        uc.mem_write(src, bytes(0x1000))
        uc.mem_write(out, bytes(0x1000))
        translator = base_b + MODE_FUNCTION_OFFSET[name]
        calc.run(uc, translator, [out, mode])
        code = struct.unpack('<I', uc.mem_read(out, 4))[0]
        context = {0x100: 0, 0x12c: 1, 0x130: code, 0x124: 0x12,
                   0x128: 0x12, 0x13c: 4, 0x10c: 8, 0x17c: 2}
        for offset, value in context.items():
            uc.mem_write(src + offset, struct.pack('<I', value))
        uc.mem_write(out, bytes(0x1000))
        calc.run(uc, selector, [src, out])
        selected = bytes(uc.mem_read(out, 1))[0]
        rows = []
        for idx in range(9):
            uc.mem_write(src + 0x13c, struct.pack('<I', idx))
            uc.mem_write(out, bytes(0x1000))
            calc.run(uc, calculate, [src, out])
            rows.append({'artificial_index': idx,
                         'four_signed16': list(struct.unpack('<4h', uc.mem_read(out + 0x3c, 8)))})
        modes.append({'mode': mode, 'firmware_name': label, 'translator': hex(translator),
                      'translated_code': code, 'selector_result': selected,
                      'context': {hex(k): v for k, v in context.items()}, 'values': rows})
    after = hashlib.sha256(path.read_bytes()).hexdigest()
    assert before == after
    result[name] = {'source_sha256_before': before, 'source_sha256_after': after,
                    'decoded_blocks_sha256': [hashlib.sha256(a).hexdigest(), hashlib.sha256(b).hexdigest()],
                    'selector_function': hex(selector), 'calculate_function': hex(calculate),
                    'settings_image_dat_offset': hex(template), 'modes': modes}
assert [[r['translated_code'], r['selector_result']] for r in result['X-H2']['modes']] == [[8, 6], [10, 8], [13, 16]]
(HERE / 'результаты.json').write_text(json.dumps(result, ensure_ascii=False, indent=2) + '\n', encoding='utf-8')
print(json.dumps({name: [{'mode': r['mode'], 'code': r['translated_code'], 'selector': r['selector_result'],
                          'indices_4_5_6': [r['values'][i]['four_signed16'] for i in (4, 5, 6)]}
                         for r in value['modes']] for name, value in result.items()}, ensure_ascii=False, indent=2))
