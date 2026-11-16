"""Сквозной скан всего DAT: целевые константы + инвентарь кода (ARM64/Thumb прологи).

Только чтение DAT.
"""
from pathlib import Path
import struct

HERE = Path(__file__).resolve().parent
DAT_NEW = Path(r'<корень проекта>\FIRMWARE\ver new\FWUP0028 (2).DAT')
TRANS = bytes.maketrans(bytes(range(256)), bytes(255 - i for i in range(256)))
OUT = HERE / 'DAT_сквозной_скан.txt'

REGIONS = [
    (0x0, 0x300274, 'заголовок DAT (сырое)'),
    (0x300274, 0x82b5e6, 'FFLZ блок 0'),
    (0x82b5e6, 0x840274, 'щель 0-1'),
    (0x840274, 0xf3e81f, 'FFLZ блок 1'),
    (0xf3e81f, 0xf40274, 'щель 1-2'),
    (0xf40274, 0x1690dab, 'FFLZ блок 2'),
    (0x1690dab, 0x24a0274, 'сырое 2->3'),
    (0x24a0274, 0x284375c, 'FFLZ блок 3 (сжатый поток)'),
    (0x284375c, 0x3cb0274, 'сырое: ресурсы/шрифты'),
    (0x3cb0274, 0x56f0274, 'ARM64 Image ядра'),
    (0x56f0274, 0x6931508, 'хвост после ядра'),
]

TARGETS = {
    '0xFF970000': [struct.pack('<I', 0xFF970000), struct.pack('>I', 0xFF970000)],
    '0xFF971000': [struct.pack('<I', 0xFF971000)],
    '0xFF972000': [struct.pack('<I', 0xFF972000)],
    '0xFF973000': [struct.pack('<I', 0xFF973000)],
    '0xFF90C300': [struct.pack('<I', 0xFF90C300), struct.pack('>I', 0xFF90C300)],
    '0xFF90E100': [struct.pack('<I', 0xFF90E100), struct.pack('<I', 0xFF90E000)],
    '0x10030001': [struct.pack('<I', 0x10030001), struct.pack('>I', 0x10030001)],
    '0x4c2ff14': [struct.pack('<I', 0x4c2ff14), struct.pack('<Q', 0x4c2ff14)],
    '0x4daa6e8': [struct.pack('<I', 0x4daa6e8), struct.pack('<Q', 0x4daa6e8)],
    'MOVDC': [b'MOVDC', b'movdc', b'MovDc'],
    'MOVDC params': [b'MOVDC_DETCTRL', b'C1AFea', b'C1BWind', b'C1BMask'],
    'аскц-адрес 0xFF9700D0': [struct.pack('<I', 0xFF9700D0)],
}


def scan(dec, regions):
    out = []
    for label, needles in TARGETS.items():
        out.append(f'=== {label} ===')
        for nd in needles:
            total = 0
            rows = []
            for a, z, nm in regions:
                s, cnt = a, 0
                first = []
                while True:
                    i = dec.find(nd, s, z)
                    if i < 0:
                        break
                    cnt += 1
                    if len(first) < 3:
                        first.append(hex(i))
                    s = i + 1
                if cnt:
                    rows.append((nm, cnt, first))
                    total += cnt
            out.append(f'  шаблон {nd.hex()} -> всего {total}')
            for nm, cnt, first in rows:
                out.append(f'      {nm}: {cnt} напр. {first}')
    return out


def code_map(dec):
    out = ['=== инвентарь кода: прологи функций ===']
    pats = {
        'ARM64 stp x29,x30,[sp,#-N]!': bytes.fromhex('fd7bbfa9'),
        'ARM64 stp x29,x30,[sp,#-N]! (вариант 2)': bytes.fromhex('fd7bbaa9'),
        'Thumb push {..,lr} (b5xx)': None,
        'Thumb-2 push.w': bytes.fromhex('2de9'),
    }
    # ARM64
    for name, pat in pats.items():
        if pat is None:
            continue
        hits = []
        s = 0
        while True:
            i = dec.find(pat, s)
            if i < 0:
                break
            hits.append(i)
            s = i + 1
        out.append(f'  {name}: {len(hits)}')
        # сгруппировать по областям
        buckets = {}
        for h in hits:
            for a, z, nm in REGIONS:
                if a <= h < z:
                    buckets[nm] = buckets.get(nm, 0) + 1
                    break
        for nm, cnt in buckets.items():
            out.append(f'      {nm}: {cnt}')
    # Thumb push с lr: байты b5 xx, где xx имеет бит 8 (0x80) — lr в списке
    thr = []
    for i in range(0, len(dec) - 2, 2):
        if dec[i] == 0xb5 and dec[i + 1] & 0x80:
            thr.append(i)
    out.append(f'  Thumb push {{...,lr}} (b5 xx, xx&0x80): {len(thr)}')
    buckets = {}
    for h in thr:
        for a, z, nm in REGIONS:
            if a <= h < z:
                buckets[nm] = buckets.get(nm, 0) + 1
                break
    for nm, cnt in buckets.items():
        out.append(f'      {nm}: {cnt}')
    return out


def main():
    dec = DAT_NEW.read_bytes().translate(TRANS)
    out = scan(dec, REGIONS)
    out.append('')
    out += code_map(dec)
    OUT.write_text('\n'.join(out) + '\n', encoding='utf-8')
    print('written', OUT)


if __name__ == '__main__':
    main()
