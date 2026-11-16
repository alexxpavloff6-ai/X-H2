"""Сверка фактов fujimod (эмулятор XP5) с нашими DAT и распакованными блоками.

Только чтение: DAT, blocks/*.bin и файлы клона fujimod не изменяются.
Запуск: python сверка_с_fujimod.py
"""
from pathlib import Path
import hashlib
import json
import struct

ROOT = Path(r'<корень проекта>')
FW = ROOT / 'Внешние_репозитории' / 'fujimod'
AN = ROOT / 'Анализ_прошивки' / 'Сравнение_версий_2026-11-16'

DAT = {
    'X-H2 5.30': ROOT / 'FIRMWARE' / 'ver 5.30' / 'FWUP0028.DAT',
    'X-H2 5.33': ROOT / 'FIRMWARE' / 'ver new' / 'FWUP0028 (2).DAT',
    'X-H2S 7.30': ROOT / 'Firmware на прочиеFuji' / 'FWUP0027.DAT',
    'X-H2S 7.31': ROOT / 'Firmware на прочиеFuji' / 'FWUP0027(new).DAT',
    'X-T5 4.31': ROOT / 'Firmware на прочиеFuji' / 'FWUP0030.DAT',
    'X-T5 4.32': ROOT / 'Firmware на прочиеFuji' / 'FWUP0030(new).DAT',
    'X100VI 1.31': ROOT / 'Firmware на прочиеFuji' / 'FPUPDATE.DAT',
}

INDEX = json.loads((AN / 'blocks' / 'index.json').read_text(encoding='utf8'))


def sha(b):
    return hashlib.sha256(b).hexdigest()


def inverted(data):
    return bytes(b ^ 0xFF for b in data)


print('=' * 78)
print('1. Идентичность DAT: размер и SHA-256 против catalog/firmware/*/firmware.json')
print('=' * 78)
for key, path in DAT.items():
    data = path.read_bytes()
    print(f'{key:12s} size={len(data):10d} sha256={sha(data)}')

for fw_id, model in (('xt5-431', 'X-T5 4.31'), ('xh2s-730', 'X-H2S 7.30')):
    row = None
    for p in FW.glob(f'catalog/firmware/*/*/firmware.json'):
        j = json.loads(p.read_text(encoding='utf8'))
        if j.get('id') == fw_id:
            row = (p, j)
            break
    assert row, fw_id
    p, j = row
    data = DAT[model].read_bytes()
    up = j['update']
    print(f'\n{model}: fujimod {fw_id} size={up["size"]} sha={up["sha256"]}')
    print(f'  наш DAT size={len(data)} sha={sha(data)}')
    print(f'  размер совпал: {up["size"] == len(data)}; SHA совпал: {up["sha256"] == sha(data)}')
    print(f'  источник факта: {p.relative_to(FW)}')

print()
print('=' * 78)
print('2. Наши распакованные блоки против streams.json (X-T5 4.31, X100VI 1.31)')
print('=' * 78)
for data_dir, model_key in (('xt5-431', 'X-T5 old'), ('x100vi-131', None)):
    sp = FW / 'crates/emulator-xp5-bringup/data' / data_dir / 'streams.json'
    if not sp.exists():
        continue
    s = json.loads(sp.read_text(encoding='utf8'))
    print(f'\n--- {data_dir}: update_sha256={s["update_sha256"]}')
    for sec in s['sections']:
        name, addr, off = sec['name'], sec['address'], sec['dat_offset']
        size = sec.get('size') or sec.get('decoded_size')
        print(f'  {name:22s} dat={off:#08x} -> {addr:#010x} size={size:9d} enc={sec["encoding"]} sha={sec["sha256"][:16]}…')
        if model_key:
            row = INDEX[model_key]['blocks']
            match = [r for r in row if r['size'] == size and r['sha256'] == sec['sha256']]
            for r in match:
                print(f'      == наш блок {r["file"]} (fflz_offset {r["fflz_offset"]}, база {r["base_guess_u64_at_8"]})')

print()
print('=' * 78)
print('3. Код по адресам из bulk.generated.json против байтов наших блоков')
print('=' * 78)
for fw_id, model in (('xt5-431', 'X-T5 old'), ('xh2-530', 'X-H2 old'), ('xh2s-730', 'X-H2S old')):
    jp = list(FW.glob('catalog/firmware/*/*/bulk.generated.json'))
    j = None
    for p in jp:
        cand = json.loads(p.read_text(encoding='utf8'))
        if cand.get('id') == f'{fw_id}-bulk':
            j = cand
            break
    if not j:
        continue
    print(f'\n--- {fw_id}')
    ok = miss = fail = 0
    for chk in j['code_checks']:
        va, size, want = chk['address'], chk['size'], chk['sha256']
        found = False
        for n, row in enumerate(INDEX[model]['blocks']):
            b = (AN / row['file']).read_bytes()
            base = struct.unpack_from('<Q', b, 8)[0] if n in (0, 1) else 0
            if base <= va and va + size <= base + len(b):
                got = sha(b[va - base:va - base + size])
                okk = got == want
                ok += okk
                fail += (not okk)
                print(f'  {"OK  " if okk else "FAIL"} {chk["name"]:16s} {va:#x}+{size}')
                found = True
                break
        if not found:
            miss += 1
            print(f'  --   {chk["name"]:16s} {va:#x}+{size} вне наших блоков')
    print(f'  итого: совпало {ok}, не совпало {fail}, вне блоков {miss}')

print()
print('=' * 78)
print('4. Заголовки сжатия method4 по смещениям из fujimod (инвертированный DAT)')
print('=' * 78)


def container_header(inv, off):
    if off + 20 > len(inv):
        return None
    unpacked, packed, pages, page_size, method = struct.unpack_from('<5I', inv, off)
    ok = (0x10000 < unpacked < 0x10000000 and 0x800 <= packed <= unpacked
          and page_size == 0x4000 and method == 4
          and pages == (packed + 0x3FFF) // 0x4000)
    return {'unpacked': unpacked, 'packed': packed, 'pages': pages, 'page_size': page_size,
            'method': method, 'valid': ok}


targets = {
    'X-T5 4.31': [0x60274, 0x1c0274, 0x300274, 0x820274, 0xf20274, 0x24a0274],
    'X100VI 1.31': [0xABC, 0xC02BC, 0x1402BC, 0x9C02BC, 0x10E02BC, 0x1A202BC],
}
for key, offsets in targets.items():
    inv = inverted(DAT[key].read_bytes())
    print(f'\n--- {key}')
    for off in offsets:
        h = container_header(inv, off)
        print(f'  dat {off:#08x}: {h}')

print()
print('=' * 78)
print('5. "boot-setup" X100VI: сырой раздел streams.json (raw = инверсия DAT)')
print('=' * 78)
inv = inverted(DAT['X100VI 1.31'].read_bytes())
for name, off, size, addr, want in (
        ('boot-setup', 0xABC, 73728, 0xFF800000, '96a39ff275db2d8593d23ee5a97b613da84ab8ed9bd98c5aa43d34e6cee71a9d'),
        ('loader-000c02bc', 0xC02BC, 123584, 0x81000, '05caba32b0b698706d3af4ccc87fd90b1ae66ee7f4a072b5bb2b6e0df0c54a09')):
    chunk = inv[off:off + size]
    print(f'{name}: -> {addr:#x} len={len(chunk)} sha={sha(chunk)} совпал={sha(chunk) == want}')
    print(f'  первые 32 байта: {chunk[:32].hex()}')
    words = struct.unpack_from('<8I', chunk, 0)
    print('  первые 8 слов LE: ' + ' '.join(f'{w:08x}' for w in words))
    strings = [s for s in chunk[:4096].split(b'\0') if len(s) >= 6 and all(32 <= c < 127 for c in s)]
    print(f'  строки в первом 4 КиБ: {[s.decode() for s in strings[:10]]}')

print()
print('=' * 78)
print('6. Наши указатели против fujimod bulk "configuration_pointer"')
print('=' * 78)
xh2 = json.loads((FW / 'catalog/firmware/xh2/5.30/bulk.generated.json').read_text(encoding='utf8'))
print('X-H2 5.30 configuration_pointer =', hex(xh2['source']['configuration_pointer']), '=', xh2['source']['configuration_pointer'])
print('  наш прежний вывод: указатель шаблона 0x20c1458 (X-H2 5.30)')
print('  совпало:', hex(xh2['source']['configuration_pointer']) == '0x20c1458')
print('X-H2 5.30 window =', hex(xh2['window']['address']), 'size', xh2['window']['size'])
print('  наш блок 1 X-H2 5.30: база', INDEX['X-H2 old']['blocks'][1]['base_guess_u64_at_8'],
      'size', INDEX['X-H2 old']['blocks'][1]['size'])
