"""Original four-model WB metadata writer, artificial 5750/5000 K inputs.
This does not emulate physical white balance, pixel processing, or whole camera.
"""
from pathlib import Path
import hashlib
import importlib.util
import json
import struct
import sys

HERE = Path(__file__).resolve().parent
ANALYSIS = HERE.parents[1]
sys.path.insert(0, str(ANALYSIS / 'инструменты'))
spec = importlib.util.spec_from_file_location('tables', ANALYSIS / 'Единый_глубокий_анализ/сопоставить_таблицы.py')
t = importlib.util.module_from_spec(spec)
spec.loader.exec_module(t)
from unicorn import Uc, UC_ARCH_ARM64, UC_MODE_ARM
from unicorn.arm64_const import UC_ARM64_REG_X19, UC_ARM64_REG_X20, UC_ARM64_REG_X30, UC_ARM64_REG_SP, UC_ARM64_REG_PC

# start/end, gate, WB mode, WB red/blue shift, ordinary temperature
CONFIG = {'X-H2': (0x2e52ca4, 0x2e52d2c, 0x3978, 0x39a4, 0x39a8, 0x3a94),
          'X-H2S': (0x3169f88, 0x316a010, 0x391c, 0x3948, 0x394c, 0x3a40),
          'X-T5': (0x2d90eec, 0x2d90f74, 0x39c0, 0x39ec, 0x39f0, 0x3ad0),
          'X100VI': (0x3060e24, 0x3060eac, 0x3fa8, 0x3fd4, 0x3fd8, 0x40c0)}
P, O, S = 0x60000000, 0x60010000, 0x70000000
results = {}
for name, (start, end, gate, mode, shift, temperature) in CONFIG.items():
    rel, expected, ao, bo, *_ = t.FILES[name]
    path = ANALYSIS.parent / rel
    raw = path.read_bytes()
    before = hashlib.sha256(raw).hexdigest()
    if before != expected:
        raise ValueError(f'Unexpected DAT hash: {name}')
    dat = raw.translate(t.base.TRANSLATION)
    a, b = t.base.unpack_fflz(dat, ao), t.base.unpack_fflz(dat, bo)
    ba, bb = struct.unpack_from('<Q', a, 8)[0], struct.unpack_from('<Q', b, 8)[0]
    u = Uc(UC_ARCH_ARM64, UC_MODE_ARM)
    u.mem_map(ba, 0x6000000 - ba)
    u.mem_write(ba, a)
    u.mem_write(bb, b)
    u.mem_map(P, 0x30000)
    u.mem_map(S, 0x10000)
    cases = []
    for k in (5750, 5000):
        u.mem_write(P, bytes(0x5000))
        u.mem_write(O, bytes(0x10000))
        for off, value in ((gate, 2), (mode, 13), (shift, 1), (shift + 4, -5)):
            u.mem_write(P + off, struct.pack('<I', value & 0xffffffff))
        u.mem_write(P + temperature, struct.pack('<H', k))
        u.reg_write(UC_ARM64_REG_X19, P)
        u.reg_write(UC_ARM64_REG_X20, O)
        u.reg_write(UC_ARM64_REG_X30, S)
        u.reg_write(UC_ARM64_REG_SP, S + 0xf000)
        u.emu_start(start, end, count=1000000)
        if u.reg_read(UC_ARM64_REG_PC) != end:
            raise RuntimeError(f'Expected stop not reached: {name}')
        region = bytes(u.mem_read(O, 0xb0))
        cases.append({'synthetic_kelvin_input': k, 'synthetic_internal_shift': [1, -5],
                      'mode_field': struct.unpack_from('<H', region, 0x98)[0],
                      'kelvin_field': struct.unpack_from('<H', region, 0x9e)[0],
                      'shift_fields': list(struct.unpack_from('<ii', region, 0xa4))})
    after = hashlib.sha256(path.read_bytes()).hexdigest()
    if before != after:
        raise RuntimeError(f'DAT changed: {name}')
    results[name] = {'source_sha256_before': before, 'source_sha256_after': after,
                     'start': hex(start), 'stop_exclusive': hex(end), 'cases': cases}
(HERE / 'результаты.json').write_text(json.dumps({'method': 'Original ARM64 fragments with synthetic input and context; no real camera or pixel pipeline, no calculated WB gains.', 'cameras': results}, ensure_ascii=False, indent=2) + '\n', encoding='utf-8')
print(json.dumps({n: r['cases'] for n, r in results.items()}, ensure_ascii=False, indent=2))
