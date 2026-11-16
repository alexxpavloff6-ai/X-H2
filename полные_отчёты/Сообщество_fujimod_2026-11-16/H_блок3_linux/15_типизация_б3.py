"""Типизация содержимого блока 3, тест «растровых ширин» для неопознанного payload,
и точные хеши областей 5.30 vs 5.33.

Только чтение DAT/blocks.
"""
from pathlib import Path
import hashlib
import struct

HERE = Path(__file__).resolve().parent
BLOCKS = HERE.parent.parent / 'Сравнение_версий_2026-11-16' / 'blocks'
DAT_NEW = Path(r'<корень проекта>\FIRMWARE\ver new\FWUP0028 (2).DAT')
DAT_OLD = Path(r'<корень проекта>\FIRMWARE\ver 5.30\FWUP0028.DAT')
TRANS = bytes.maketrans(bytes(range(256)), bytes(255 - i for i in range(256)))
OUT = HERE / 'B3_типизация.txt'

CHUNK = 0x10000


def f32_stats(b):
    n = len(b) // 4
    if n == 0:
        return 0.0, 0.0, 0.0
    vals = struct.unpack_from(f'<{n}f', b)
    finite = 0
    small = 0
    ints = 0
    for v in vals:
        if v != v or v in (float('inf'), float('-inf')):
            continue
        finite += 1
        a = abs(v)
        if 1e-6 < a < 1e6:
            small += 1
        if v == int(v) and a < 1e7:
            ints += 1
    return finite / n, small / n, ints / n


def u16_stats(b):
    n = len(b) // 2
    if n == 0:
        return 0.0
    vals = struct.unpack_from(f'<{n}H', b)
    small = sum(1 for v in vals if v < 0x1000)
    return small / n


def periodic10(b):
    lim = min(len(b) - 10, 0x2000)
    return sum(1 for i in range(lim) if b[i] == b[i + 10]) / max(lim, 1)


def width_corr(b, widths):
    res = []
    for w in widths:
        n = len(b) // w
        if n < 4:
            continue
        same = 0
        tot = 0
        for r in range(n - 1):
            a = b[r * w:(r + 1) * w]
            c = b[(r + 1) * w:(r + 2) * w]
            same += sum(1 for x, y in zip(a, c) if x == y)
            tot += w
        res.append((w, same / tot))
    return sorted(res, key=lambda x: -x[1])


def main():
    b3 = (BLOCKS / 'X-H2_5.33_b3_0x24a0274.bin').read_bytes()
    dec_new = DAT_NEW.read_bytes().translate(TRANS)
    dec_old = DAT_OLD.read_bytes().translate(TRANS)
    out = []

    out.append('=== типизация блока 3 по 64-КиБ чанкам ===')
    out.append('смещение   f32-финит  f32-умерен  f32-целые  u16<0x1000  период10  H-оценка')
    import math
    from collections import Counter
    for o in range(0, len(b3), CHUNK):
        seg = b3[o:o + CHUNK]
        f, s, i = f32_stats(seg)
        u = u16_stats(seg)
        p = periodic10(seg)
        c = Counter(seg)
        n = len(seg)
        H = -sum(v / n * math.log2(v / n) for v in c.values())
        out.append(f'0x{o:07x}  {f:8.3f}  {s:9.3f}  {i:8.3f}  {u:9.3f}  {p:7.3f}  {H:6.2f}')
    out.append('')

    out.append('=== тест растровых ширин ===')
    cands = [160, 240, 320, 384, 400, 480, 512, 600, 640, 720, 768, 800, 960, 1024,
             1152, 1200, 1280, 1440, 1536, 1600, 1920, 2048]
    for label, seg in (('блок 3, хвост 0x6f0000..0x70d548 (4-байт. пиксели с 0xff)',
                        b3[0x6f0000:0x70d548]),
                       ('неопознанный payload @0x2300274 (1.5 МБ)',
                        dec_new[0x2300274:0x2476dab - 0x200])):
        out.append(f'-- {label}, {len(seg)} байт --')
        best = width_corr(seg, cands)
        for w, c in best[:6]:
            out.append(f'   ширина {w}: доля совпадающих байт между строками {c*100:.1f}%')
        out.append('')
    out.append('')

    out.append('=== хеши областей: 5.30 vs 5.33 ===')
    ranges = [
        (0x0, 0x300274, 'заголовок DAT'),
        (0x24a0274, 0x284375c, 'сжатый поток блока 3'),
        (0x1690dab, 0x24a0274, 'сырое 2->3'),
        (0x284375c, 0x3cb0274, 'ресурсы/шрифты/FDL'),
        (0x3cb0274, 0x56f0274, 'ARM64 Image ядра (с initramfs)'),
        (0x3c40274, 0x3c40274 + 0x2ca1, 'DTB'),
        (0x413b474, 0x413b474 + 14209, 'ikconfig (сжатый)'),
        (0x56f0274, 0x6931508, 'хвост после ядра (M4/манифест)'),
    ]
    for a, z, nm in ranges:
        x = dec_new[a:z]
        y = dec_old[a:z]
        diff = sum(1 for p, q in zip(x, y) if p != q)
        out.append(f'  0x{a:x}..0x{z:x} {nm}: размер 0x{z-a:x}, различий {diff} '
                   f'({diff/max(len(x),1)*100:.2f}%), sha 5.33={hashlib.sha256(x).hexdigest()[:16]} '
                   f'5.30={hashlib.sha256(y).hexdigest()[:16]}, равны={x == y}')
    out.append('')
    out.append('=== блок 3 по моделям ===')
    for name in ('X-H2_5.33_b3_0x24a0274.bin', 'X-H2_5.30_b3_0x24a0274.bin',
                 'X-H2S_7.31_b3_0x24a0274.bin', 'X-T5_4.32_b3_0x24a0274.bin'):
        d = (BLOCKS / name).read_bytes()
        out.append(f'  {name}: {len(d)} байт sha256={hashlib.sha256(d).hexdigest()}')
    OUT.write_text('\n'.join(out) + '\n', encoding='utf-8')
    print('written', OUT)


if __name__ == '__main__':
    main()
