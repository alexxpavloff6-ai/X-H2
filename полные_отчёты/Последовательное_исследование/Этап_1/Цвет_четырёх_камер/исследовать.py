"""Execute model-specific saturation metadata conversions on identical synthetic inputs."""
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
from unicorn.arm64_const import UC_ARM64_REG_X0, UC_ARM64_REG_X30, UC_ARM64_REG_SP, UC_ARM64_REG_PC
from capstone import Cs, CS_ARCH_ARM64, CS_MODE_LITTLE_ENDIAN

CONFIG = {'X-H2': (0x2e51064, 0x3978, 0x39b8, 0x39b4),
          'X-H2S': (0x3168340, 0x391c, 0x395c, 0x3958),
          'X-T5': (0x2d8f19c, 0x39c0, 0x3a00, 0x39fc),
          'X100VI': (0x305f144, 0x3fa8, 0x3fe8, 0x3fe4)}
FILM_FUNCTION = {'X-H2': 0x2e516fc, 'X-H2S': 0x31689e4,
                 'X-T5': 0x2d8f8b4, 'X100VI': 0x305f888}
EXPECTED = [0xe0, 0xc0, 0x100, 0x80, 0, 0x180, 0x400, 0x4c0, 0x4e0]
results = {}
md = Cs(CS_ARCH_ARM64, CS_MODE_LITTLE_ENDIAN)
for name, (fn, gate, mode, color) in CONFIG.items():
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
    uc.mem_map(0x60000000, 0x10000)
    uc.mem_map(0x70000000, 0x10000)

    def execute(g, m, c, pc=fn):
        uc.mem_write(0x60000000, bytes(0x5000))
        for offset, value in ((gate, g), (mode, m), (color, c)):
            uc.mem_write(0x60000000 + offset, struct.pack('<I', value))
        uc.reg_write(UC_ARM64_REG_X0, 0x60000000)
        uc.reg_write(UC_ARM64_REG_X30, 0x70000000)
        uc.reg_write(UC_ARM64_REG_SP, 0x7000f000)
        uc.emu_start(pc, 0x70000000, count=100000)
        assert uc.reg_read(UC_ARM64_REG_PC) == 0x70000000
        return uc.reg_read(UC_ARM64_REG_X0) & 0xffffffff

    values = [execute(2, 19, i) for i in range(9)]
    assert values == EXPECTED
    controls = [{'gate': g, 'mode': m, 'color': c, 'return': execute(g, m, c)}
                for g, m, c in ((2, 4, 3), (46, 19, 3), (2, 19, 9))]
    film = [{'mode': m, 'return': execute(2, m, 4, FILM_FUNCTION[name])}
            for m in (0, 4, 13, 19, 22)]
    assert [r['return'] for r in film] == [0, 0xffff, 0x600, 0x800, 0xb00]
    first_instructions = [f'{ins.address:08x} {ins.bytes.hex()} {ins.mnemonic} {ins.op_str}'
                          for ins in md.disasm(b[fn-base_b:fn-base_b+32], fn)]
    after = hashlib.sha256(path.read_bytes()).hexdigest()
    assert before == after
    results[name] = {'source_sha256_before': before, 'source_sha256_after': after,
                     'function': hex(fn), 'field_gate': hex(gate), 'field_mode': hex(mode),
                     'field_color': hex(color), 'inputs': {'gate': 2, 'mode': 19, 'color': list(range(9))},
                     'outputs': values, 'controls': controls, 'first_instructions': first_instructions,
                     'film_function': hex(FILM_FUNCTION[name]), 'film_conversions': film,
                     'block_sha256': [hashlib.sha256(a).hexdigest(), hashlib.sha256(b).hexdigest()]}
(HERE / 'результаты.json').write_text(json.dumps(results, ensure_ascii=False, indent=2) + '\n', encoding='utf-8')
print(json.dumps({name: {'outputs': r['outputs'], 'controls': r['controls'], 'film': r['film_conversions']} for name, r in results.items()}, ensure_ascii=False, indent=2))
