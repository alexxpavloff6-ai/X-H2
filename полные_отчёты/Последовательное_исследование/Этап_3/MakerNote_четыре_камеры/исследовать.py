"""Unpatched ARM64 MakerNote fragments, synthetic RAM only; run from any directory."""
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
from unicorn import Uc, UC_ARCH_ARM64, UC_MODE_ARM, UC_HOOK_CODE, UC_HOOK_MEM_READ
from unicorn.arm64_const import UC_ARM64_REG_X0, UC_ARM64_REG_X19, UC_ARM64_REG_X20, UC_ARM64_REG_X30, UC_ARM64_REG_SP, UC_ARM64_REG_PC

# film writer start, saturation writer start, builder, predicate, table selector, header,
# parameter gate/mode/color offsets. Writer fragments enter with x19=params, x20=object.
CONFIG = {
    'X-H2': (0x2e537c8, 0x2e52cbc, 0x13503e4, 0x134df8c, 0x134fd68, 0x134fbf0, 0x3978, 0x39b8, 0x39b4),
    'X-H2S': (0x316a994, 0x3169fa0, 0x166dfc4, 0x166bb6c, 0x166d948, 0x166d7d0, 0x391c, 0x395c, 0x3958),
    'X-T5': (0x2d91a90, 0x2d90f04, 0x134d3b4, 0x134af5c, 0x134cd38, 0x134cbc0, 0x39c0, 0x3a00, 0x39fc),
    'X100VI': (0x3061b1c, 0x3060e3c, 0x14376ac, 0x14350f8, 0x1437030, 0x1436eb8, 0x3fa8, 0x3fe8, 0x3fe4),
}
PARAMS, OBJ, BUF, STACK, STOP = 0x60000000, 0x60010000, 0x60020000, 0x70000000, 0x70000000
sha = lambda b: hashlib.sha256(b).hexdigest()

def put32(uc, address, value):
    uc.mem_write(address, struct.pack('<I', value))

def get32(uc, address):
    return struct.unpack('<I', uc.mem_read(address, 4))[0]

def run(uc, start, args=(), end=STOP, regs=None):
    for i, v in enumerate(args):
        uc.reg_write(UC_ARM64_REG_X0 + i, v)
    for r, v in (regs or {}).items():
        uc.reg_write(r, v)
    uc.reg_write(UC_ARM64_REG_SP, STACK + 0xf000)
    uc.reg_write(UC_ARM64_REG_X30, STOP)
    uc.emu_start(start, end, count=2000000)
    if uc.reg_read(UC_ARM64_REG_PC) != end:
        raise RuntimeError(f'instruction limit at {uc.reg_read(UC_ARM64_REG_PC):x}')
    return uc.reg_read(UC_ARM64_REG_X0)

def new_vm(images):
    uc = Uc(UC_ARCH_ARM64, UC_MODE_ARM)
    uc.mem_map(images[0][0], 0x6000000 - images[0][0])
    # The X100VI images overlap; this preserves the established project's load order.
    for base, image in images:
        uc.mem_write(base, image)
    uc.mem_map(PARAMS, 0x40000)
    uc.mem_map(STACK, 0x10000)
    return uc

def records(data, tag):
    prefix = struct.pack('<HHI', tag, 3, 1)
    return [{'offset': i, 'bytes': data[i:i+12].hex(' ')}
            for i in range(len(data)-11) if data[i:i+8] == prefix]

results = {}
for name, config in CONFIG.items():
    film, sat, builder, pred, selector, header, gate, mode, color = config
    rel, expected, ao, bo, *_ = tables.FILES[name]
    path = ANALYSIS.parent / rel
    raw = path.read_bytes()
    before = sha(raw)
    if before != expected:
        raise RuntimeError(f'{name}: unexpected DAT hash {before}')
    decoded = raw.translate(tables.base.TRANSLATION)
    images = []
    for off in (ao, bo):
        image = tables.base.unpack_fflz(decoded, off)
        images.append((struct.unpack_from('<Q', image, 8)[0], image))
    uc = new_vm(images)
    table = run(uc, selector, [2])
    descriptors = {}
    # Group 2 entries are 40-byte descriptors. Search only within that group,
    # stopping after its 0x1401 entry plus a safe bound; verify by builder reads.
    for i in range(256):
        addr = table + 40*i
        entry = bytes(uc.mem_read(addr, 40))
        tag, typ, count = struct.unpack_from('<H2xHI', entry)
        if tag in (0x1003, 0x1401) and typ == 3 and count == 1:
            descriptors[f'{tag:04x}'] = {'address': hex(addr), 'bytes': entry.hex(' '),
                                          'source_offset': hex(struct.unpack_from('<Q', entry, 32)[0])}
    if len(descriptors) != 2:
        raise RuntimeError(f'{name}: missing descriptors: {descriptors}')
    hlen = run(uc, header, [BUF])
    header_bytes = bytes(uc.mem_read(BUF, hlen)).hex(' ')
    cases = []
    inputs = [(m, c, 2, None) for m in (13, 19, 22) for c in (4, 3, 2)]
    inputs += [(19, 3, 2, 0), (4, 3, 2, None), (19, 3, 46, None), (19, 9, 2, None)]
    for m, c, g, override in inputs:
        uc = new_vm(images)
        for off, val in ((gate, g), (mode, m), (color, c)):
            put32(uc, PARAMS + off, val)
        regs = {UC_ARM64_REG_X19: PARAMS, UC_ARM64_REG_X20: OBJ}
        run(uc, film, end=film+0x1c, regs=regs)
        run(uc, sat, end=sat+0xc, regs=regs)
        if override is not None:
            put32(uc, OBJ+0x18c, override)
        value_film = struct.unpack('<H', uc.mem_read(OBJ+0x190, 2))[0]
        value_sat = struct.unpack('<H', uc.mem_read(OBJ+0x9a, 2))[0]
        flag = get32(uc, OBJ+0x18c)
        observed = {'predicate_calls': [], 'descriptor_reads': {'1003': 0, '1401': 0}}
        def code_hook(u, address, size, _):
            if address == pred:
                tag = u.reg_read(UC_ARM64_REG_X0+1) & 0xffff
                if tag in (0x1003, 0x1401):
                    observed['predicate_calls'].append({'tag': hex(tag), 'group': u.reg_read(UC_ARM64_REG_X0), 'object': hex(u.reg_read(UC_ARM64_REG_X0+2))})
        def read_hook(u, access, address, size, value, _):
            for tag, desc in descriptors.items():
                start = int(desc['address'], 16)
                if address < start+40 and address+size > start:
                    observed['descriptor_reads'][tag] += 1
        code_handle = uc.hook_add(UC_HOOK_CODE, code_hook, begin=pred, end=pred)
        read_handle = uc.hook_add(UC_HOOK_MEM_READ, read_hook)
        length = run(uc, builder, [2, OBJ, BUF, BUF])
        data = bytes(uc.mem_read(BUF, length))
        uc.hook_del(code_handle)
        uc.hook_del(read_handle)
        predicates = {f'{tag:04x}': run(uc, pred, [2, tag, OBJ]) for tag in (0x1401, 0x1003)}
        cases.append({'input': {'gate': g, 'mode': m, 'color': c, 'override_film_flag': override},
                      'film_value': value_film, 'saturation_value': value_sat, 'film_flag_18c': flag,
                      'predicates': predicates, 'builder_observed': observed,
                      'directory_length': length, 'directory_sha256': sha(data),
                      'records': {f'{t:04x}': records(data, t) for t in (0x1401, 0x1003)}})
    after = sha(path.read_bytes())
    if after != before:
        raise RuntimeError(f'{name}: DAT changed')
    results[name] = {'dat': str(rel), 'sha256_before': before, 'sha256_after': after,
                     'images': [{'base': hex(base), 'length': len(image), 'sha256': sha(image)} for base, image in images],
                     'addresses': {'film_writer_fragment': hex(film), 'saturation_writer_fragment': hex(sat),
                                   'builder': hex(builder), 'predicate': hex(pred), 'selector': hex(selector), 'header': hex(header)},
                     'parameter_offsets': {'gate': hex(gate), 'mode': hex(mode), 'color': hex(color)},
                     'selector_group_2': hex(table), 'descriptors': descriptors,
                     'header_bytes': header_bytes, 'cases': cases}
(HERE/'результат.json').write_text(json.dumps(results, ensure_ascii=False, indent=2)+'\n', encoding='utf-8')
print(json.dumps({n: {'header': v['header_bytes'], 'cases': len(v['cases'])} for n,v in results.items()}, ensure_ascii=False))
