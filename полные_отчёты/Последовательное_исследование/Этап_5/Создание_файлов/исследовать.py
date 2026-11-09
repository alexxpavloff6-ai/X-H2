"""Исследование буферного сериализатора, без файловых вызовов; DAT только читаются."""
from pathlib import Path
import hashlib, importlib.util, json, re, struct, sys
sys.dont_write_bytecode = True
HERE = Path(__file__).resolve().parent
ROOT = HERE.parents[3]
AN = ROOT / 'Анализ_прошивки'
spec = importlib.util.spec_from_file_location('raw_prior', AN / 'Полная_взаимосвязь/RAW_JPEG/исследовать.py')
prior = importlib.util.module_from_spec(spec)
spec.loader.exec_module(prior)
from unicorn import Uc, UC_ARCH_ARM64, UC_MODE_ARM, UC_HOOK_CODE
from unicorn.arm64_const import UC_ARM64_REG_X0, UC_ARM64_REG_X1, UC_ARM64_REG_X2, UC_ARM64_REG_X30, UC_ARM64_REG_SP, UC_ARM64_REG_PC

sha = lambda data: hashlib.sha256(data).hexdigest()
def digest(path):
    h = hashlib.sha256()
    with path.open('rb') as f:
        for chunk in iter(lambda: f.read(1048576), b''):
            h.update(chunk)
    return h.hexdigest()

def find(blocks, needle):
    return [a + m.start() for a, b in blocks for m in re.finditer(re.escape(needle), b)]

def dispatch(blocks):
    from unicorn.arm64_const import UC_ARM64_REG_X20, UC_ARM64_REG_X21, UC_ARM64_REG_X25
    result = []
    for event in (0x34, 0x33, 0x96):
        u = Uc(UC_ARCH_ARM64, UC_MODE_ARM)
        u.mem_map(0x40000, 0x5fc0000)
        for a, b in blocks:
            u.mem_write(a, b)
        u.mem_map(0x70000000, 0x10000)
        u.mem_write(0x70001000, struct.pack('<I', event))
        for reg, value in ((UC_ARM64_REG_X20, 0x70001000), (UC_ARM64_REG_X21, 0x70002000), (UC_ARM64_REG_X25, 0), (UC_ARM64_REG_SP, 0x7000f000)):
            u.reg_write(reg, value)
        seen = []
        def stop(uc, address, count, user):
            word = struct.unpack('<I', bytes(uc.mem_read(address, 4)))[0]
            if word >> 26 == 0x25 or address == 0x2e4db48:
                seen.append({'pc': hex(address), 'instruction_hex': struct.pack('<I', word).hex(), 'x0': hex(uc.reg_read(UC_ARM64_REG_X0)), 'x1': hex(uc.reg_read(UC_ARM64_REG_X1))})
                uc.emu_stop()
        u.hook_add(UC_HOOK_CODE, stop)
        u.emu_start(0x2e4e928, 0, count=100)
        if not seen:
            raise RuntimeError(('dispatch', event, hex(u.reg_read(UC_ARM64_REG_PC))))
        result.append({'event': event, 'stop_before_call_or_out_of_range_branch': seen[0]})
    return result

def examine(blocks, start, name):
    # До первого копирования включительно; отрицательная ветвь остановлена до возврата.
    good = start + 0x54
    bad = start + 0x1c4
    result = []
    for size, seed in [(0xaf, 0x21), (0xb0, 0x21), (0xb1, 0x83)]:
        u = Uc(UC_ARCH_ARM64, UC_MODE_ARM)
        u.mem_map(0x40000, 0x5fc0000)
        for a, b in blocks:
            u.mem_write(a, b)
        u.mem_map(0x70000000, 0x50000)
        output, source, obj, sizeptr = 0x70001000, 0x70002000, 0x70010000, 0x70030000
        data = bytes((seed + i * 7) & 255 for i in range(0x30))
        initial = bytes([0xa5]) * 0x100
        u.mem_write(source, data)
        u.mem_write(output, initial)
        u.mem_write(sizeptr, struct.pack('<I', size))
        u.mem_write(obj + 0x13270, struct.pack('<Q', source))
        u.mem_write(obj + 0x13278, struct.pack('<I', 0x80))
        u.mem_write(obj + 0x13290, struct.pack('<Q', source + len(data)))
        for reg, value in ((UC_ARM64_REG_X0, output), (UC_ARM64_REG_X1, sizeptr), (UC_ARM64_REG_X2, obj), (UC_ARM64_REG_SP, 0x7004f000), (UC_ARM64_REG_X30, 0x70040000)):
            u.reg_write(reg, value)
        seen = []
        def stop(uc, address, count, user):
            if address in (good, bad):
                seen.append(address)
                uc.emu_stop()
        u.hook_add(UC_HOOK_CODE, stop)
        u.emu_start(start, 0, count=10000)
        if not seen:
            raise RuntimeError((name, hex(u.reg_read(UC_ARM64_REG_PC))))
        final = bytes(u.mem_read(output, len(initial)))
        result.append({'capacity': size, 'source_hex': data.hex(), 'output_initial_hex': initial.hex(), 'output_final_hex': final.hex(), 'stop': hex(seen[0]), 'copied_source': final[:len(data)] == data, 'rest_unchanged': final[len(data):] == initial[len(data):], 'output_unchanged': final == initial})
    return result

def main():
    inputs = [(ROOT / filename, expected) for _, filename, expected, _, _ in prior.MODELS]
    before = {str(path.relative_to(ROOT)): digest(path) for path, _ in inputs}
    for path, expected in inputs:
        if before[str(path.relative_to(ROOT))] != expected:
            raise ValueError('Unexpected input hash: ' + str(path))
    all_results = []
    signature = None
    for name, filename, expected, offsets, starts in prior.MODELS:
        raw = (ROOT / filename).read_bytes()
        if sha(raw) != expected:
            raise ValueError('Changed input while reading: ' + filename)
        decoded = raw.translate(prior.base.TRANSLATION)
        blocks = [(addr, prior.base.unpack_fflz(decoded, off)) for off, addr in zip(offsets, starts)]
        if signature is None:
            b = blocks[0][1]
            signature = bytes(b[0x134cea8-starts[0]:0x134cee8-starts[0]])
        candidates = find(blocks, signature)
        item = {'model': name, 'input': filename, 'blocks': [{'base': hex(a), 'size': len(b), 'sha256': sha(b)} for a, b in blocks], 'exact_64_byte_serializer_signature_hex': signature.hex(), 'signature_hits': [hex(x) for x in candidates]}
        for term in ('recbjpeg', 'recblsraw', 'recbmedia', 'LIST_JPEG_COMP', 'LIST_JPEG_COMP_RAF'):
            item.setdefault('string_hits', {})[term] = [hex(x) for x in find(blocks, term.encode() + b'\0')]
        if name in ('X-H2 5.30', 'X-H2S 7.30'):
            start = {'X-H2 5.30': 0x134cea8, 'X-H2S 7.30': 0x166aa88}[name]
            if candidates != [start]:
                raise ValueError((name, candidates))
            item['serializer_context'] = prior.code(blocks, start, 0x1cc)
            item['vm_cases'] = examine(blocks, start, name)
        if name == 'X-H2 5.30':
            item['maker_buffer_context'] = prior.code(blocks, 0x2dde56c, 0x134)
            item['dispatcher_context'] = prior.code(blocks, 0x13410f0, 0x90)
            item['record_task_context'] = prior.code(blocks, 0x2e4e964, 0x84)
            item['record_dispatch_context'] = prior.code(blocks, 0x2e4e8b0, 0xac) + prior.code(blocks, 0x2e4e0f0, 0x30)
            item['record_to_owner_context'] = prior.code(blocks, 0x2e3bcd8, 0x170)
            item['record_dispatch_vm'] = dispatch(blocks)
        all_results.append(item)
    after = {str(path.relative_to(ROOT)): digest(path) for path, _ in inputs}
    if before != after:
        raise ValueError('Input DAT changed during analysis')
    result = {'input_sha256_before': before, 'input_sha256_after': after, 'limitations': 'Only two FFLZ regions per model; exact 64-byte signature is not semantic equivalence. No filesystem or media service executed; output exists only in Unicorn RAM. VM stops after the first original copy or at the insufficient-capacity branch; no mocked successful write.', 'models': all_results}
    (HERE / 'результат.json').write_text(json.dumps(result, ensure_ascii=False, indent=2) + '\n', encoding='utf-8')
    for item in all_results:
        print(item['model'], item['signature_hits'], [(x['capacity'], x['stop'], x['copied_source'], x['output_unchanged']) for x in item.get('vm_cases', [])])

if __name__ == '__main__':
    main()
