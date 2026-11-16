"""Разбор сырых областей DAT вне FFLZ: сегментация, строки, сигнатуры, различия 5.30/5.33.

Только чтение DAT.
"""
from pathlib import Path
import hashlib
import math
import re
import struct
from collections import Counter

HERE = Path(__file__).resolve().parent
DAT_NEW = Path(r'<корень проекта>\FIRMWARE\ver new\FWUP0028 (2).DAT')
DAT_OLD = Path(r'<корень проекта>\FIRMWARE\ver 5.30\FWUP0028.DAT')
TRANS = bytes.maketrans(bytes(range(256)), bytes(255 - i for i in range(256)))
OUT = HERE / 'DAT_сырые_разбор.txt'

REGIONS = [
    (0x0, 0x300274, 'заголовок DAT'),
    (0x1690dab, 0x24a0274, 'между блоком 2 и блоком 3'),
    (0x284375c, 0x3cb0274, 'после блока 3 до Image'),
    (0x3cb0274, 0x56f0274, 'ARM64 Image ядра (27.5 МиБ, с initramfs)'),
    (0x56f0274, 0x6931508, 'хвост после ядра'),
]

ASCII = re.compile(rb'[\x20-\x7e]{8,}')
SIGS = {
    'JPEG SOI': b'\xff\xd8\xff', 'PNG': b'\x89PNG\r\n\x1a', 'RIFF': b'RIFF', 'BMP': b'BM',
    'TIFF-le': b'II*\x00', 'TIFF-be': b'MM\x00*', 'PCX': b'\x0a\x05\x01\x08',
    'fujifilm': b'Fujifilm', 'FUJIFILM': b'FUJIFILM', 'X-H2': b'X-H2', 'FF': b'Fujifilm',
    'ISGC': b'ISGC', 'isgc': b'isgc', 'MOVDC': b'MOVDC', 'DSP': b'DSP', 'MILBEAUT': b'MILBEAUT',
    'Milbeaut': b'Milbeaut', 'socionext': b'socionext', 'Socionext': b'Socionext',
    'ThreadX': b'ThreadX', 'uboot': b'U-Boot', 'u-boot': b'U-Boot',
    'banner': b'Linux version', 'cpp': b'.cpp', 'cfile': b'.c\x00',
    'sensor': b'sensor', 'lens': b'lens', 'calib': b'calib', 'CALIB': b'CALIB',
    'AF': b'AF_', 'move': b'mov', 'Sony': b'Sony', 'IMX': b'IMX',
}
INTERESTING = re.compile(
    rb'(?:MOVDC|SENSOR|LENS|AF_|ISGC|DSP|CALIB|FIRM|FIRMWARE|BOOT|U-BOOT|X-H2|FUJI|'
    rb'VERSION|VER:|BUILD|20[0-9][0-9]/[0-9]|error|ERR|assert|%s|%d)')


def entropy(b):
    if not b:
        return 0.0
    c = Counter(b)
    n = len(b)
    return -sum(v / n * math.log2(v / n) for v in c.values())


def main():
    dec_new = DAT_NEW.read_bytes().translate(TRANS)
    dec_old = DAT_OLD.read_bytes().translate(TRANS)
    out = []
    for a, z, nm in REGIONS:
        seg = dec_new[a:z]
        out.append(f'===== 0x{a:x}..0x{z:x} ({nm}) len=0x{z-a:x} H={entropy(seg):.2f} =====')
        asc = list(ASCII.finditer(seg))
        out.append(f'  ASCII-строк >=8: {len(asc)}')
        # интересные строки
        shown = 0
        for m in asc:
            s = m.group()
            if INTERESTING.search(s) and shown < 60:
                out.append(f'    0x{a+m.start():08x} {s[:90]!r}')
                shown += 1
        out.append('  сигнатуры:')
        for label, pat in SIGS.items():
            hits = []
            s = 0
            while True:
                i = seg.find(pat, s)
                if i < 0:
                    break
                hits.append(hex(a + i))
                s = i + 1
                if len(hits) >= 5:
                    hits.append('...')
                    break
            if hits:
                out.append(f'    {label}: {hits}')
        # первые байты
        out.append(f'  начало: {seg[:64].hex(" ")}')
        out.append(f'  конец : {seg[-64:].hex(" ")}')
        out.append('')
    # различие 5.30 vs 5.33 в области после блока 3
    a, z = 0x284375c, 0x6931508
    n = z - a
    diff_runs = []
    cur = None
    step = 0x10000
    for o in range(a, z, step):
        x = dec_new[o:o + step]
        y = dec_old[o:o + step]
        if x != y:
            cnt = sum(1 for p, q in zip(x, y) if p != q)
            diff_runs.append((o, cnt))
    out.append(f'===== различия 5.30 vs 5.33 в 0x{a:x}..0x{z:x} (шаг 0x10000) =====')
    out.append(f'  различающихся блоков по 64КиБ: {len(diff_runs)} из {(z-a)//step}')
    for o, cnt in diff_runs[:80]:
        out.append(f'    0x{o:08x}: {cnt} байт различий')
    OUT.write_text('\n'.join(out) + '\n', encoding='utf-8')
    print('written', OUT)
    print('diff blocks:', len(diff_runs))


if __name__ == '__main__':
    main()
