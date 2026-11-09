"""Original per-camera tone writers on synthetic structures, not a camera pipeline."""
from pathlib import Path
import hashlib
import importlib.util
import json
import struct
import sys

HERE = Path(__file__).resolve().parent
ANALYSIS = HERE.parents[2]
sys.path.insert(0, str(ANALYSIS / 'инструменты'))
spec = importlib.util.spec_from_file_location('tables', ANALYSIS / 'Единый_глубокий_анализ/сопоставить_таблицы.py')
tables = importlib.util.module_from_spec(spec)
spec.loader.exec_module(tables)
from unicorn import Uc, UC_ARCH_ARM64, UC_MODE_ARM
from unicorn.arm64_const import UC_ARM64_REG_X0, UC_ARM64_REG_X1, UC_ARM64_REG_X2, UC_ARM64_REG_X3, UC_ARM64_REG_X30, UC_ARM64_REG_SP, UC_ARM64_REG_PC
from capstone import Cs, CS_ARCH_ARM64, CS_MODE_LITTLE_ENDIAN

# writer shadow/highlight, gate, shadow/highlight input, disable, special selector, special override
CONFIG = {
    'X-H2': (0x2e4f7bc, 0x2e4f90c, 0x3978, 0x3a90, 0x3a8c, 0x3f00, 0x3f58, 0x3f88),
    'X-H2S': (0x3166ab8, 0x3166c08, 0x391c, 0x3a3c, 0x3a38, 0x3eac, 0x3f04, 0x3f34),
    'X-T5': (0x2d8d844, 0x2d8d99c, 0x39c0, 0x3acc, 0x3ac8, 0x3f38, 0x40bc, 0x40ec),
    'X100VI': (0x305d79c, 0x305d900, 0x3fa8, 0x40bc, 0x40b8, 0x4528, 0x46bc, 0x46ec),
}
BUILDERS = {'X-H2': (0x13503e4, 0x134df8c), 'X-H2S': (0x166dfc4, 0x166bb6c),
            'X-T5': (0x134d3b4, 0x134af5c), 'X100VI': (0x14376ac, 0x14350f8)}
PARAM, OBJ, BUF, STACK, STOP = 0x60000000, 0x60010000, 0x60020000, 0x70000000, 0x70000000
md = Cs(CS_ARCH_ARM64, CS_MODE_LITTLE_ENDIAN)
results = {}
for name, (shadow_fn, highlight_fn, gate, shadow_off, highlight_off, disable, selector, override) in CONFIG.items():
    rel, expected_sha, ao, bo, *_ = tables.FILES[name]
    path = ANALYSIS.parent / rel
    raw = path.read_bytes()
    before = hashlib.sha256(raw).hexdigest()
    assert before == expected_sha
    data = raw.translate(tables.base.TRANSLATION)
    a, b = tables.base.unpack_fflz(data, ao), tables.base.unpack_fflz(data, bo)
    base_a, base_b = struct.unpack_from('<Q', a, 8)[0], struct.unpack_from('<Q', b, 8)[0]
    uc = Uc(UC_ARCH_ARM64, UC_MODE_ARM)
    uc.mem_map(base_a, 0x6000000 - base_a)
    uc.mem_write(base_a, a)
    uc.mem_write(base_b, b)
    uc.mem_map(PARAM, 0x30000)
    uc.mem_map(STACK, 0x10000)

    def run(shadow, highlight, g=2, disabled=0, sel=0, over=0, zero_obj=False):
        uc.mem_write(PARAM, bytes(0x5000))
        uc.mem_write(OBJ, bytes(0x10000) if zero_obj else b'\xa5' * 0x200)
        for off, val in ((gate, g), (shadow_off, shadow), (highlight_off, highlight),
                         (disable, disabled), (selector, sel), (override, over)):
            uc.mem_write(PARAM + off, struct.pack('<I', val))
        for fn in (shadow_fn, highlight_fn):
            uc.reg_write(UC_ARM64_REG_X0, PARAM)
            uc.reg_write(UC_ARM64_REG_X1, OBJ)
            uc.reg_write(UC_ARM64_REG_X30, STOP)
            uc.reg_write(UC_ARM64_REG_SP, STACK + 0xf000)
            uc.emu_start(fn, STOP, count=100000)
            assert uc.reg_read(UC_ARM64_REG_PC) == STOP
        region = bytes(uc.mem_read(OBJ + 0x120, 16))
        return {'input': [shadow, highlight], 'gate': g, 'disable': disabled,
                'selector': sel, 'override': over,
                'object_0x120_0x12f_hex': region.hex(' '),
                'shadow_i32': struct.unpack_from('<i', region, 4)[0],
                'highlight_i32': struct.unpack_from('<i', region, 8)[0]}

    cases = [run(s, h) for s, h in ((8, 8), (9, 11), (8, 11), (9, 8))]
    builder, predicate = BUILDERS[name]
    builder_cases = []
    for s, h in ((8, 8), (9, 11), (8, 11), (9, 8)):
        row = run(s, h, zero_obj=True)
        uc.mem_write(BUF, bytes(0x10000))
        def call(fn, args):
            for reg, value in zip((UC_ARM64_REG_X0, UC_ARM64_REG_X1, UC_ARM64_REG_X2, UC_ARM64_REG_X3), args):
                uc.reg_write(reg, value)
            uc.reg_write(UC_ARM64_REG_X30, STOP)
            uc.reg_write(UC_ARM64_REG_SP, STACK + 0xf000)
            uc.emu_start(fn, STOP, count=1000000)
            assert uc.reg_read(UC_ARM64_REG_PC) == STOP
            return uc.reg_read(UC_ARM64_REG_X0)
        row['predicates'] = [call(predicate, (2, tag, OBJ)) for tag in (0x1040, 0x1041)]
        length = call(builder, (2, OBJ, BUF, BUF))
        assert length <= 0x10000
        directory = bytes(uc.mem_read(BUF, length))
        row['directory_length'] = length
        row['directory_sha256'] = hashlib.sha256(directory).hexdigest()
        row['records'] = {}
        for tag in (0x1040, 0x1041):
            prefix = struct.pack('<HHI', tag, 9, 1)
            positions = [i for i in range(len(directory) - 11) if directory[i:i+8] == prefix]
            row['records'][f'0x{tag:04x}'] = [
                {'offset': i, 'bytes': directory[i:i+12].hex(' ')} for i in positions]
        builder_cases.append(row)
    boundaries = [run(v, v) for v in (*range(18), 0xffffffff)]
    conditions = [run(9, 11, g=g, disabled=d, sel=s, over=o) for g, d, s, o in (
        (44, 0, 1, 0), (45, 0, 0, 0), (45, 0, 1, 0), (45, 0, 2, 0),
        (45, 0, 3, 0), (46, 0, 1, 0), (45, 0, 1, 1), (2, 1, 0, 0),
        (45, 1, 1, 0), (45, 1, 3, 0))]
    insns = {}
    for label, fn, end in (('shadow', shadow_fn, highlight_fn), ('highlight', highlight_fn, highlight_fn + (highlight_fn - shadow_fn))):
        insns[label] = [f'{i.address:08x} {i.bytes.hex(" ")} {i.mnemonic} {i.op_str}'
                        for i in md.disasm(b[fn-base_b:end-base_b], fn) if i.address < end]
    after = hashlib.sha256(path.read_bytes()).hexdigest()
    assert before == after
    results[name] = {'dat': str(rel), 'sha256_before': before, 'sha256_after': after,
                     'decoded_blocks_sha256': [hashlib.sha256(a).hexdigest(), hashlib.sha256(b).hexdigest()],
                     'writer_shadow': hex(shadow_fn), 'writer_highlight': hex(highlight_fn),
                     'parameter_offsets': dict(zip(('gate', 'shadow', 'highlight', 'disable', 'selector', 'override'),
                                                   map(hex, (gate, shadow_off, highlight_off, disable, selector, override)))),
                     'output_offsets': {'shadow': '0x124', 'highlight': '0x128'},
                     'builder': hex(builder), 'predicate': hex(predicate), 'builder_cases': builder_cases,
                     'cases': cases, 'boundary_cases': boundaries, 'condition_cases': conditions,
                     'disassembly': insns}
result = {'method': 'Original decoded firmware instructions in Unicorn, no code patches. Artificial parameter RAM at 0x60000000 and output object at 0x60010000, zeroed params; writer cases object initialized to a5; builder cases object zeroed. Synthetic stack and return. Researcher separately invokes each writer, predicate and this camera builder; zero-filled mapped globals, no UI conversion or real file path exercised.', 'cameras': results}
(HERE / 'результаты.json').write_text(json.dumps(result, ensure_ascii=False, indent=2) + '\n', encoding='utf-8')
print(json.dumps({n: {'cases': r['cases'], 'conditions': r['condition_cases']} for n, r in results.items()}, ensure_ascii=False, indent=2))
