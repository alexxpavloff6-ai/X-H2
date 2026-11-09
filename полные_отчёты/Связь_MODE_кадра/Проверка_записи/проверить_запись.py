"""Execute the saved MODE reader and its original 16-bit writer in Unicorn.
The writer's bounds helper is stubbed; this is not a physical camera or file.
"""
from pathlib import Path
import hashlib
import importlib.util
import json
import struct

HERE = Path(__file__).resolve().parent
ROOT = HERE.parents[2]
spec = importlib.util.spec_from_file_location('bridge', HERE.parent / 'X-H2S_X-T5' / 'исследовать.py')
b = importlib.util.module_from_spec(spec)
spec.loader.exec_module(b)
from unicorn import Uc, UC_ARCH_ARM64, UC_MODE_ARM, UC_HOOK_CODE
from unicorn.arm64_const import UC_ARM64_REG_X0, UC_ARM64_REG_X30, UC_ARM64_REG_PC

bounds = {'X-H2S': (0x2f0eca8, 0x29d9e9c), 'X-T5': (0x2b369f0, 0x25fa75c)}
results = {}
for name, c in b.MODELS.items():
    source = ROOT / 'Firmware на прочиеFuji' / c['file']
    raw = source.read_bytes()
    assert hashlib.sha256(raw).hexdigest() == c['sha']
    data = raw.translate(b.base.TRANSLATION)
    blocks = [(0x40000, data[0x60274:0x7e5b4])]
    blocks.extend((address, b.base.unpack_fflz(data, off)) for off, address in zip(c['offsets'], c['starts']))
    u = Uc(UC_ARCH_ARM64, UC_MODE_ARM)
    u.mem_map(0x40000, 0x5fc0000)
    for addr, block in blocks:
        u.mem_write(addr, block)
    u.mem_map(0x60000000, 0x40000)
    u.mem_map(0x70000000, 0x10000)
    helper, output = bounds[name]
    results[name] = []
    for ui, helper_result in ((14, 0), (0, 0), (14, 1)):
        b.put(u, c['ui'], ui)
        b.put(u, c['old'], 0xffffffff)
        b.put(u, c['state'], 0xffffffff)
        b.put(u, c['error'], 0)
        b.reset(u, {})
        b.run(u, c['compare'], {c['stop']})
        state = b.get(u, c['state'])
        assert state == (13 if ui == 14 else 0)
        b.put(u, 0x60000000, 0)
        u.mem_write(output, b'\xaa\xbb')
        b.reset(u, {0: 0x60000000})
        calls = []
        def intercept(uc, address, size, user):
            if address == helper:
                calls.append({'helper': hex(address), 'synthetic_return': helper_result})
                uc.reg_write(UC_ARM64_REG_X0, helper_result)
                uc.reg_write(UC_ARM64_REG_PC, uc.reg_read(UC_ARM64_REG_X30))
        hook = u.hook_add(UC_HOOK_CODE, intercept)
        try:
            u.emu_start(c['reader'], 0x70000000, count=200000, timeout=3000000)
        finally:
            u.hook_del(hook)
        assert u.reg_read(UC_ARM64_REG_PC) == 0x70000000 and len(calls) == 1
        count = b.get(u, 0x60000000)
        result = bytes(u.mem_read(output, 2)).hex()
        expected = ('0b00' if ui == 14 else '0100') if helper_result == 0 else 'aabb'
        assert result == expected and count == (2 if helper_result == 0 else 0)
        results[name].append({'ui': ui, 'mode': state, 'helper_return_synthetic': helper_result,
                              'writer_output_address': hex(output), 'bytes_before': 'aabb',
                              'bytes_after': result, 'synthetic_counter_after': count, 'helper_calls': calls})
    assert hashlib.sha256(source.read_bytes()).hexdigest() == c['sha']
spec2 = importlib.util.spec_from_file_location('bridge_hx100', HERE.parent / 'X-H2_X100VI' / 'исследовать.py')
h = importlib.util.module_from_spec(spec2)
spec2.loader.exec_module(h)
settings = {
    'X-H2': dict(new=0x2053f70, old=0x2051c90, flags=[0x2051408, 0x267ebec],
                 compare=0x132d138, stop=0x132d5e0, reader=0x2bfacb4,
                 helper=0x2bf66d0, output=0x26be0c4),
    'X100VI': dict(new=0x20b7178, old=0x20b4ec0, flags=[0x20b44c4, 0x2897414, 0x27f601c],
                   compare=0x1411a3c, stop=0x1411fb4, reader=0x2df7c6c,
                   helper=0x2df31d0, output=0x284170c),
}
for model in h.models:
    name = model['name']
    c = settings[name]
    source = ROOT / model['path']
    raw = source.read_bytes()
    assert hashlib.sha256(raw).hexdigest() == model['sha']
    data = raw.translate(b.base.TRANSLATION)
    u = Uc(UC_ARCH_ARM64, UC_MODE_ARM)
    u.mem_map(0x40000, 0x5fc0000)
    for off, addr in zip(model['offsets'], model['bases']):
        block = b.base.unpack_fflz(data, off)
        assert struct.unpack_from('<Q', block, 8)[0] == addr
        u.mem_write(addr, block)
    u.mem_map(0x60000000, 0x40000)
    u.mem_map(0x70000000, 0x10000)
    results[name] = []
    for ui, helper_result in ((14, 0), (0, 0), (14, 1)):
        b.put(u, c['new'], ui)
        b.put(u, c['old'], 0 if ui == 14 else 14)
        b.put(u, model['state'], 0)
        for flag in c['flags']:
            b.put(u, flag, 0)
        b.reset(u, {})
        b.run(u, c['compare'], {c['stop']})
        state = b.get(u, model['state'])
        assert state == (13 if ui == 14 else 0)
        b.put(u, 0x60000000, 0)
        u.mem_write(c['output'], b'\xaa\xbb')
        b.reset(u, {0: 0x60000000})
        calls = []
        def intercept_hx(uc, address, size, user):
            if address == c['helper']:
                calls.append({'helper': hex(address), 'synthetic_return': helper_result})
                uc.reg_write(UC_ARM64_REG_X0, helper_result)
                uc.reg_write(UC_ARM64_REG_PC, uc.reg_read(UC_ARM64_REG_X30))
        hook = u.hook_add(UC_HOOK_CODE, intercept_hx)
        try:
            u.emu_start(c['reader'], 0x70000000, count=200000, timeout=3000000)
        finally:
            u.hook_del(hook)
        assert u.reg_read(UC_ARM64_REG_PC) == 0x70000000 and len(calls) == 1
        count = b.get(u, 0x60000000)
        value = bytes(u.mem_read(c['output'], 2)).hex()
        expected = ('0b00' if ui == 14 else '0100') if helper_result == 0 else 'aabb'
        assert value == expected and count == (2 if helper_result == 0 else 0)
        results[name].append({'ui': ui, 'mode': state, 'helper_return_synthetic': helper_result,
                              'writer_output_address': hex(c['output']), 'bytes_before': 'aabb',
                              'bytes_after': value, 'synthetic_counter_after': count, 'helper_calls': calls})
    assert hashlib.sha256(source.read_bytes()).hexdigest() == model['sha']
(HERE / 'результаты.json').write_text(json.dumps(results, ensure_ascii=False, indent=2) + '\n', encoding='utf-8')
print(json.dumps(results, ensure_ascii=False, indent=2))
