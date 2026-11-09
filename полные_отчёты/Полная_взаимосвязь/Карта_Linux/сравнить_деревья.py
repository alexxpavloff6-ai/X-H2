"""Read FDT directly from four firmware files; never write source DAT files."""
from pathlib import Path
import hashlib
import json
import struct

HERE = Path(__file__).resolve().parent
ROOT = HERE.parents[2]
TRANS = bytes.maketrans(bytes(range(256)), bytes(255 - i for i in range(256)))
SOURCES = {
    'X-H2': ('FIRMWARE/ver 5.30/FWUP0028.DAT', 'be47168cb075ef726e67cb4bb08175a896047a3b0de2bcb6e65333b22cfcb203', 0x3c40274),
    'X-H2S': ('Firmware на прочиеFuji/FWUP0027.DAT', '87c566c1ff6343e4c7463a4ef968183f41d1f24cc63d610433d3a387b13f731b', 0x3c40274),
    'X-T5': ('Firmware на прочиеFuji/FWUP0030.DAT', '790d6deecf26766188b0e506e40645e6b816addfeba39a52334349405421724e', 0x3c40274),
    'X100VI': ('Firmware на прочиеFuji/FPUPDATE.DAT', '0d48d2ae26ac7ebab9b0e4cac56324807ec1ea8ae30df06b0b9e79066dc0a14a', 0x43002bc),
}

def sha(b):
    return hashlib.sha256(b).hexdigest()

def parse_fdt(data):
    magic, total, off_struct, off_strings, off_reserve, version, last, boot, strings_size, struct_size = struct.unpack_from('>10I', data)
    assert magic == 0xd00dfeed and version == 17 and total == len(data)
    assert off_struct + struct_size <= total and off_strings + strings_size <= total
    s = data[off_struct:off_struct + struct_size]
    names = data[off_strings:off_strings + strings_size]
    pos = 0
    stack = []
    nodes = []
    ended = False
    while pos < len(s):
        token = struct.unpack_from('>I', s, pos)[0]
        pos += 4
        if token == 1:
            end = s.index(b'\0', pos)
            part = s[pos:end].decode('ascii')
            pos = (end + 4) & ~3
            stack.append(part)
            nodes.append({'path': '/' + '/'.join(x for x in stack if x), 'properties': {}})
        elif token == 2:
            assert stack
            stack.pop()
        elif token == 3:
            length, nameoff = struct.unpack_from('>II', s, pos)
            pos += 8
            assert nameoff < len(names) and pos + length <= len(s)
            name = names[nameoff:names.index(b'\0', nameoff)].decode('ascii')
            assert nodes and name not in nodes[-1]['properties']
            nodes[-1]['properties'][name] = s[pos:pos + length].hex()
            pos = (pos + length + 3) & ~3
        elif token == 4:
            continue
        elif token == 9:
            ended = True
            break
        else:
            raise ValueError(f'Unknown FDT token {token} at {pos - 4:#x}')
    assert ended and not stack
    return {'version': version, 'length': total, 'nodes': nodes}

results = {}
for model, (path, expected, offset) in SOURCES.items():
    p = ROOT / path
    raw = p.read_bytes()
    assert sha(raw) == expected
    decoded = raw.translate(TRANS)
    assert decoded[offset:offset + 4] == bytes.fromhex('d00dfeed')
    size = struct.unpack_from('>I', decoded, offset + 4)[0]
    assert 40 <= size <= 2_000_000 and offset + size <= len(decoded)
    tree = decoded[offset:offset + size]
    parsed = parse_fdt(tree)
    nodes = parsed['nodes']
    shared = []
    for n in nodes:
        if n['path'].count('/') != 1:
            continue
        if not any(n['path'].startswith('/' + x) for x in ('memory@', 'amp_shared@', 'rpmsg_shared@', 'amp_isgc_shared@')):
            continue
        prop = n['properties']
        reg = bytes.fromhex(prop['reg'])
        assert len(reg) == 16
        addr, length = struct.unpack('>QQ', reg)
        compat = bytes.fromhex(prop.get('compatible', '')).rstrip(b'\0').decode('ascii')
        shared.append({'path': n['path'], 'address': hex(addr), 'size': hex(length), 'compatible': compat})
    assert len(shared) == 4
    literals = {hex(v): tree.find(struct.pack('>I', v)) for v in (0xff96c634, 0xff96c638, 0xff96c000)}
    cpus = [n['path'] for n in nodes if n['path'].startswith('/cpus/cpu@')]
    assert len(cpus) == 4
    results[model] = {'source': path, 'source_sha256': expected, 'dt_dat_offset': hex(offset),
                      'dt_sha256': sha(tree), 'dt_size': size, 'version': parsed['version'],
                      'node_count': len(nodes), 'cpu_nodes': cpus, 'memory_regions': shared,
                      'literal_be_offsets_in_tree': literals, 'nodes': nodes}
    assert sha(p.read_bytes()) == expected
(HERE / 'деревья.json').write_text(json.dumps(results, ensure_ascii=False, indent=2) + '\n', encoding='utf-8')
print(json.dumps({name: {k: v for k, v in record.items() if k != 'nodes'} for name, record in results.items()}, ensure_ascii=False, indent=2))
