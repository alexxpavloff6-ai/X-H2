"""Где лежит образ companion Cortex-M4 в наших DAT (X-H2/X-H2S/X-T5/X100VI).

Только чтение DAT и blocks/*.bin. Ничего не изменяет.
Запуск: python companion_M4.py > companion_M4_вывод.txt
Опирается на факты fujimod: A53-функция копирования (X-T5 0x13F7B58,
X-H2 0x13FB194) читает дескриптор секции id=3 и копирует flash -> 0xFA200000;
таблица дескрипторов лежит в прелоаде 0x10C0000 (X-T5/X-H2) из flash 0x1A0000.
"""
from pathlib import Path
import hashlib
import struct
import sys

ROOT = Path(r'<корень проекта>')
sys.path.insert(0, str(ROOT / 'Анализ_прошивки' / 'Сравнение_версий_2026-11-16'))
from capstone import Cs, CS_ARCH_ARM, CS_MODE_THUMB  # noqa: E402

DAT = {
    'X-T5 4.31': (ROOT / 'Firmware на прочиеFuji' / 'FWUP0030.DAT', 0x10C0000),
    'X-T5 4.32': (ROOT / 'Firmware на прочиеFuji' / 'FWUP0030(new).DAT', 0x10C0000),
    'X-H2 5.30': (ROOT / 'FIRMWARE' / 'ver 5.30' / 'FWUP0028.DAT', 0x10C0000),
    'X-H2 5.33': (ROOT / 'FIRMWARE' / 'ver new' / 'FWUP0028 (2).DAT', 0x10C0000),
    'X-H2S 7.30': (ROOT / 'Firmware на прочиеFuji' / 'FWUP0027.DAT', 0x13E0000),
    'X-H2S 7.31': (ROOT / 'Firmware на прочиеFuji' / 'FWUP0027(new).DAT', 0x13E0000),
    'X100VI 1.31': (ROOT / 'Firmware на прочиеFuji' / 'FPUPDATE.DAT', None),
}
PRELOAD_DAT = 0x1A0274   # flash 0x1A0000 + dat_origin 0x274
PRELOAD_BYTES = 0x800

_cache = {}


def inverted(path):
    if path not in _cache:
        _cache[path] = bytes(b ^ 0xFF for b in path.read_bytes())
    return _cache[path]


def sha(b):
    return hashlib.sha256(b).hexdigest()


def parse_table(data, preload_off, preload_va):
    """Разобрать таблицу компонентных дескрипторов (0x40 байт на запись)."""
    ptr = struct.unpack_from('<Q', data, preload_off)[0]
    if preload_va is None or not (preload_va <= ptr < preload_va + PRELOAD_BYTES):
        return ptr, []
    table_off = preload_off + (ptr - preload_va)
    rows = []
    for i in range(PRELOAD_BYTES // 0x40):
        w = struct.unpack_from('<16I', data, table_off + i * 0x40)
        row = {
            'index': i,
            'dat_off': table_off + i * 0x40,
            'id': w[0],
            'addr': w[2] | (w[3] << 32),
            'size': w[4] | (w[5] << 32),
            'end': w[6] | (w[7] << 32),
            'bss': w[8] | (w[9] << 32),
            'flash': w[10] | (w[11] << 32),
            'fsz': w[12] | (w[13] << 32),
        }
        rows.append(row)
        if row['id'] == 0xFFFFFFFF:
            break
    return ptr, rows


print('=' * 78)
print('1. Таблица компонентных дескрипторов (flash 0x1A0000 -> VA 0x10C0000)')
print('=' * 78)
m4 = {}
for name, (path, va) in DAT.items():
    data = inverted(path)
    if va is None:
        ptr = struct.unpack_from('<Q', data, PRELOAD_DAT)[0]
        print(f'\n--- {name}: u64 @DAT 0x1A0274 = {ptr:#x} (не 0x10C0050 — своя раскладка)')
        continue
    ptr, rows = parse_table(data, PRELOAD_DAT, va)
    print(f'\n--- {name}: указатель {ptr:#x}, записей {len(rows)}')
    for r in rows:
        print('  id={id:2d} addr={addr:#011x} size={size:#09x} end={end:#09x} '
              'bss={bss:#09x} flash={flash:#09x} fsz={fsz:#09x} (DAT {dat_off:#x})'.format(**r))
        if r['id'] == 3:
            m4[name] = (path, r)

print()
print('=' * 78)
print('2. Образ Cortex-M4: DAT 0x1C0274, размер из дескриптора id=3')
print('=' * 78)
imgs = {}
for name, (path, r) in m4.items():
    data = inverted(path)
    off = r['flash'] + 0x274
    size = int(r['size'])
    img = data[off:off + size]
    imgs[name] = img
    print(f'\n--- {name}: flash {r["flash"]:#x} -> DAT {off:#x}, size {size:#x} ({size} Б), '
          f'bss {r["bss"]:#x}, sha256 {sha(img)[:16]}…')
    vec = struct.unpack_from('<16I', img, 0)
    print('  вектор-таблица:', ' '.join(f'{v:08x}' for v in vec))
    print(f'  SP={vec[0]:#x}  reset={vec[1]:#x} (Thumb: {vec[1] & 1 == 1})')
    bad = [i for i, v in enumerate(vec) if v and (v & 1 == 0 or v >= size)]
    print('  записей вне Thumb/размера:', bad)
    irq = []
    i = 16
    while i * 4 + 4 <= len(img):
        v = img[i * 4] | (img[i * 4 + 1] << 8) | (img[i * 4 + 2] << 16) | (img[i * 4 + 3] << 24)
        if v == 0:
            break
        irq.append(v)
        i += 1
    print(f'  IRQ-векторов: {len(irq)}, из них {len(set(irq))} уникальных, '
          f'диапазон {min(irq):#x}..{max(irq):#x}')
    # литералы локальных адресов M4 (peripheral alias = phys - 0x60000000)
    for lit in (0x5F90E100, 0x5F90E120, 0x5F928000, 0x5F911000, 0x5F90E300, 0x5F9B0000,
                0x68473000, 0x6263D000):
        p = struct.pack('<I', lit)
        hits = []
        s = 0
        while True:
            j = img.find(p, s)
            if j < 0:
                break
            hits.append(j)
            s = j + 1
        if hits:
            print(f'  литерал {lit:#010x}: {len(hits)} вхождений, первые '
                  + ', '.join(f'{h:#x}' for h in hits[:5]))
    # хвост образа
    nonzero = max((i for i, b in enumerate(img) if b), default=-1)
    print(f'  последний ненулевой байт: {nonzero:#x} (размер {size:#x}); '
          f'хвост нулевой: {nonzero < size - 1}')

print()
print('=' * 78)
print('3. Совпадение образов M4 между моделями')
print('=' * 78)
names = list(imgs)
for i in range(len(names)):
    for j in range(i + 1, len(names)):
        a, b = names[i], names[j]
        x, y = imgs[a], imgs[b]
        n = min(len(x), len(y))
        same = sum(1 for k in range(0, n, 4096) if x[k:k + 4096] == y[k:k + 4096])
        print(f'  {a} vs {b}: размеры {len(x):#x}/{len(y):#x}, '
              f'совпало 4К-страниц {same}/{n // 4096}, sha {"равны" if sha(x) == sha(y) else "разные"}')

print()
print('=' * 78)
print('4. Дизассемблер Thumb: reset и несколько обработчиков (X-H2 5.30)')
print('=' * 78)
img = imgs.get('X-H2 5.30')
if img:
    cs = Cs(CS_ARCH_ARM, CS_MODE_THUMB)
    for va in (0x0A00, 0x18B6, 0x18DC, 0x18B2, 0x2132):
        print(f'\n--- local {va:#x} ---')
        for k, ins in enumerate(cs.disasm(img[va:va + 96], va)):
            print(f'  {ins.address:05x}: {ins.mnemonic:8s} {ins.op_str}')
            if k >= 22:
                break

print()
print('=' * 78)
print('5. A53: release-регистр и его таблица (X-H2 5.30, block 0)')
print('=' * 78)
from fwcommon import load, dis, find_bytes, bl_callers  # noqa: E402
b = load('X-H2', 'old', 0)
print('таблица адресов 0x18F4688:')
for i in range(18):
    print(f'  idx {i:2d} -> {b.u64(0x18F4688 + i * 8):#x}')
print('маска 0x18F47D0:', [hex(b.u32(0x18F47D0 + i * 4)) for i in range(18)])
print('\nчтение (0x13AD588):', dis(b, 0x13AD588, 14))
print('\nзапись (0x13AD514):', dis(b, 0x13AD514, 18))
print('\nкопирование M4 в X-H2 5.30 (0x13FB178):')
print(dis(b, 0x13FB178, 46))
print('\nкол-во вызовов memcpy 0x14D2534 из блока 0:', len(bl_callers(b, 0x14D2534)))

print()
print('=' * 78)
print('6. X100VI: где его таблица/образ (поиск 0x40-записей с id=3)')
print('=' * 78)
data = inverted(DAT['X100VI 1.31'][0])
best = []
for off in range(0x274, 0x300274, 4):
    if struct.unpack_from('<I', data, off)[0] != 3:
        continue
    w = struct.unpack_from('<16I', data, off)
    flash = w[10] | (w[11] << 32)
    size = w[4] | (w[5] << 32)
    if 0x1000 < size < 0x1000000 and flash and flash < 0x6000000 and (w[1] | (w[1] << 32)) == 0:
        # первый u32 следующей записи должен быть != 3 и таблица должна иметь терминатор
        nxt = struct.unpack_from('<I', data, off + 0x40)[0]
        if nxt < 0x100:
            best.append((off, w[0], w[2] | (w[3] << 32), size, flash, w[8] | (w[9] << 32)))
for row in best[:12]:
    print(f'  DAT {row[0]:#x}: id={row[1]} addr={row[2]:#x} size={row[3]:#x} flash={row[4]:#x} bss={row[5]:#x}')
print('  кандидатов:', len(best))
