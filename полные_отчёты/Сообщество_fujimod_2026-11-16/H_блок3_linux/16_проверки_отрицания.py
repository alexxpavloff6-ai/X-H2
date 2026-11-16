"""Проверки к выводам:
1) ADRP на страницы MOVDC/mailbox/clock во всех ARM64-областях DAT (блоки 0-2 и ядро).
2) Плотность прологов функций в блоке 3 против блока 0 (контроль «это код»).
3) Трансформации неопознанного payload 0x2300274 (бит-реверс, ниббл-свап, XOR 0xFF) + Thumb-оценка.
4) Точные различающиеся байты хвоста 5.30/5.33 и манифест с git-commit.
Только чтение DAT/blocks.
"""
from pathlib import Path
import struct
import sys

HERE = Path(__file__).resolve().parent
ROOT = HERE.parent.parent / 'Сравнение_версий_2026-11-16'
BLOCKS = ROOT / 'blocks'
DAT_NEW = Path(r'<корень проекта>\FIRMWARE\ver new\FWUP0028 (2).DAT')
DAT_OLD = Path(r'<корень проекта>\FIRMWARE\ver 5.30\FWUP0028.DAT')
TRANS = bytes.maketrans(bytes(range(256)), bytes(255 - i for i in range(256)))
OUT = HERE / 'проверки_отрицания.txt'

sys.path.insert(0, str(ROOT.parent / 'инструменты'))
from capstone import Cs, CS_ARCH_ARM, CS_MODE_THUMB, CS_ARCH_ARM64, CS_MODE_LITTLE_ENDIAN  # noqa: E402


def adrp_pages(data, base, pages):
    """ADRP, нацеленные на указанные страницы (по декодированию инструкции)."""
    hits = {p: [] for p in pages}
    cs = Cs(CS_ARCH_ARM64, CS_MODE_LITTLE_ENDIAN)
    n = len(data) - 3
    for o in range(0, n, 4):
        w = struct.unpack_from('<I', data, o)[0]
        if (w & 0x9f000000) != 0x90000000:
            continue
        immlo = (w >> 29) & 3
        immhi = (w >> 5) & 0x7ffff
        imm = (immhi << 2) | immlo
        if imm & (1 << 20):
            imm -= 1 << 21
        pc = base + o
        target = (pc & ~0xfff) + (imm << 12)
        for p in pages:
            if target == p:
                hits[p].append(pc)
    return hits


def main():
    dec = DAT_NEW.read_bytes().translate(TRANS)
    b0 = (BLOCKS / 'X-H2_5.33_b0_0x300274.bin').read_bytes()
    b1 = (BLOCKS / 'X-H2_5.33_b1_0x840274.bin').read_bytes()
    b2 = (BLOCKS / 'X-H2_5.33_b2_0xf40274.bin').read_bytes()
    b3 = (BLOCKS / 'X-H2_5.33_b3_0x24a0274.bin').read_bytes()
    base0 = struct.unpack_from('<Q', b0, 8)[0]
    base1 = struct.unpack_from('<Q', b1, 8)[0]
    out = []

    out.append('=== 1. ADRP на целевые страницы ===')
    pages = [0xff970000, 0xff971000, 0xff972000, 0xff973000, 0xff974000,
             0xff90c000, 0xff90e000, 0x4c2f000, 0x4c3b000, 0x4daa000]
    kernel = dec[0x3cb0274:0x56f0274]
    for label, data, base in (('блок 0', b0, base0), ('блок 1', b1, base1),
                              ('блок 2', b2, 0), ('ядро Linux', kernel, 0x3cb0274),
                              ('заголовок DAT', dec[0:0x300274], 0)):
        hits = adrp_pages(data, base, pages)
        out.append(f'-- {label} (база 0x{base:x}, размер 0x{len(data):x}) --')
        for p in pages:
            out.append(f'   страница 0x{p:x}: {len(hits[p])} ADRP'
                       + (f' напр. {[hex(x) for x in hits[p][:5]]}' if hits[p] else ''))
    out.append('')

    out.append('=== 2. плотность прологов функций (контроль) ===')
    def counts(data):
        a64 = 0
        for o in range(0, len(data) - 3, 4):
            w = struct.unpack_from('<I', data, o)[0]
            if (w & 0xffc07fff) == 0xa9807bfd:
                a64 += 1
        thr = sum(1 for i in range(0, len(data) - 1, 2) if data[i] == 0xb5 and data[i + 1] & 0x80)
        return a64, thr
    for label, data in (('блок 0 (код A53, контроль)', b0),
                        ('блок 1 (код A53, контроль)', b1),
                        ('блок 2 (код A53, контроль)', b2),
                        ('блок 3 (полезная нагрузка)', b3),
                        ('ресурсы/шрифты', dec[0x284375c:0x3cb0274]),
                        ('M4-хвост (Thumb, контроль)', dec[0x68e5274:0x690f274])):
        a64, thr = counts(data)
        out.append(f'   {label}: ARM64-прологов {a64} на 0x{len(data):x} байт '
                   f'({a64/max(len(data),1)*1e6:.1f} на МБ), Thumb push {thr} '
                   f'({thr/max(len(data),1)*1e6:.0f} на МБ)')
    out.append('')

    out.append('=== 3. трансформации payload @0x2300274 ===')
    blob = dec[0x2300274:0x2476dab - 0x200]
    out.append(f'   размер {len(blob)} (0x{len(blob):x}), первые 32: {blob[:32].hex(" ")}')
    trans = {
        'как есть': blob,
        'XOR 0xFF': bytes(c ^ 0xff for c in blob),
        'бит-реверс байта': bytes(int(f'{c:08b}'[::-1], 2) for c in blob),
        'ниббл-свап': bytes(((c & 15) << 4) | (c >> 4) for c in blob),
        'реверс бит в 16-бит.слове': b''.join(
            struct.pack('<H', int(f'{w:016b}'[::-1], 2))
            for w in struct.unpack_from(f'<{len(blob)//2}H', blob)),
    }
    from collections import Counter
    import math
    cs_thumb = Cs(CS_ARCH_ARM, CS_MODE_THUMB)
    for name, data in trans.items():
        c = Counter(data[:0x2000])
        n = 0x2000
        H = -sum(v / n * math.log2(v / n) for v in c.values())
        zero = data.count(0) / len(data)
        # Thumb-оценка: доля 16-битных половин, которые capstone декодирует
        ok = 0
        tot = 0
        for k in range(0, min(len(data), 0x4000) - 1, 2):
            tot += 1
            if next(iter(cs_thumb.disasm(bytes(data[k:k + 2]), 0)), None) is not None:
                ok += 1
        ascii_runs = sum(1 for i in range(len(data) - 8)
                         if all(32 <= x < 127 for x in data[i:i + 8]))
        out.append(f'   {name}: H(2КиБ)={H:.2f} доля 0x00={zero*100:.1f}% '
                   f'Thumb-декод={ok/max(tot,1)*100:.1f}% ASCII-окон(8)= {ascii_runs}')
    out.append('')

    out.append('=== 4. хвост 5.30 vs 5.33: различия по байтам ===')
    dec_old = DAT_OLD.read_bytes().translate(TRANS)
    a, z = 0x56f0274, 0x6931508
    diffs = [i for i in range(a, z) if dec[i] != dec_old[i]]
    out.append(f'   различающихся байт: {len(diffs)}')
    if diffs:
        # сгруппировать
        groups = []
        cur = [diffs[0], diffs[0]]
        for d in diffs[1:]:
            if d - cur[1] <= 16:
                cur[1] = d
            else:
                groups.append(tuple(cur))
                cur = [d, d]
        groups.append(tuple(cur))
        for s, e in groups[:20]:
            out.append(f'   0x{s:x}..0x{e:x}: 5.33={dec[s:e+1].hex()} | 5.30={dec_old[s:e+1].hex()}')
    out.append('')
    out.append('=== 5. манифест в хвосте (0x6840274) ===')
    for o in (0x6840274, 0x68492d8, 0x6850334):
        seg = dec[o:o + 0x100]
        txt = ''.join(chr(c) if 32 <= c < 127 else '.' for c in seg)
        out.append(f'   0x{o:x}: {txt}')
    OUT.write_text('\n'.join(out) + '\n', encoding='utf-8')
    print('written', OUT)


if __name__ == '__main__':
    main()
