"""Read-only: decode the FFLZ blocks of the old/new X-H2, X-H2S, X-T5 firmware
into blocks/*.bin plus blocks/index.json for the version-diff workers.
DAT files are only read; nothing is written next to them."""
from pathlib import Path
import hashlib, importlib.util, json, struct, sys

HERE = Path(__file__).resolve().parent
ROOT = HERE.parent.parent
spec = importlib.util.spec_from_file_location('fwbase', HERE.parent / 'анализ_файла.py')
fwbase = importlib.util.module_from_spec(spec); spec.loader.exec_module(fwbase)

PAIRS = {
    'X-H2':  (('5.30', ROOT/'FIRMWARE/ver 5.30/FWUP0028.DAT'), ('5.33', ROOT/'FIRMWARE/ver new/FWUP0028 (2).DAT')),
    'X-H2S': (('7.30', ROOT/'Firmware на прочиеFuji/FWUP0027.DAT'), ('7.31', ROOT/'Firmware на прочиеFuji/FWUP0027(new).DAT')),
    'X-T5':  (('4.31', ROOT/'Firmware на прочиеFuji/FWUP0030.DAT'), ('4.32', ROOT/'Firmware на прочиеFuji/FWUP0030(new).DAT')),
}

def find_blocks(data):
    found = []
    for off in range(0x274, len(data) - 20, 0x1000):
        usize, csize, pages, page_size, align = struct.unpack_from('<5I', data, off)
        if not (0x10000 < usize < 0x10000000 and 0x1000 < csize <= usize and off + csize <= len(data)):
            continue
        if page_size not in (0x4000, 0x8000, 0x10000, 0x1000, 0x2000):
            continue
        try:
            block = fwbase.unpack_fflz(data, off)
        except ValueError:
            continue
        found.append((off, block))
    return found

def main():
    out = HERE / 'blocks'; out.mkdir(exist_ok=True)
    index = {}
    for model, versions in PAIRS.items():
        for state, (ver, path) in zip(('old', 'new'), versions):
            data = path.read_bytes().translate(fwbase.TRANSLATION)
            rows = []
            for n, (off, block) in enumerate(find_blocks(data)):
                name = f'{model}_{ver}_b{n}_{off:#x}.bin'
                (out / name).write_bytes(block)
                base = struct.unpack_from('<Q', block, 8)[0]
                rows.append({'fflz_offset': hex(off), 'file': f'blocks/{name}', 'size': len(block),
                             'base_guess_u64_at_8': hex(base), 'sha256': hashlib.sha256(block).hexdigest()})
            index[f'{model} {state}'] = {'version': ver, 'dat': str(path), 'blocks': rows}
            print(model, state, ver, [(r['fflz_offset'], r['base_guess_u64_at_8']) for r in rows], flush=True)
    (out / 'index.json').write_text(json.dumps(index, indent=2, ensure_ascii=False), encoding='utf8')

if __name__ == '__main__':
    main()
