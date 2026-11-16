"""Локализация патча «lens 0x411 / MF linear» во всех трёх моделях (old и new).

Ищет не по абсолютным адресам (они сдвигаются), а по сигнатурам инструкций:
  S1  cmp wN,#0x411 + cset wM,eq + str wM,[sp,#imm]      -> новый флаг request+0x50
  S2  movz w0,#0xe4 + ldr x1,[sp,#..] + strh w0,[x1,#0xa0] + movz w19,#0x8c
                                                          -> спецветка нов. диспетчера
  S3  movz w0,#0x1dba + ... + strh w0,[x1,#0xa0]         -> старое значение out+0xa0
  S4  movz w0,#0x1db3 + ... + and w19,w0,#0xff           -> старое значение шага
  S5  ldr wN,[xN,#0x50] + cbz wN,<addr> между S2 и S3    -> чтение флага
  S6  movz w0,#0x205c / #0x205e                          -> helper ND/TELE

Запуск:  python b1_locate.py  [--json]
Пишет b1_sites.json в этой папке. Только чтение блоков.
"""
import json
import struct
import sys
from pathlib import Path

HERE = Path(__file__).resolve().parent
sys.path.insert(0, str(HERE.parent))
from fwcommon import load, MODELS, cs  # noqa: E402
import capstone  # noqa: E402

D = capstone.Cs(capstone.CS_ARCH_ARM64, capstone.CS_MODE_LITTLE_ENDIAN)


def dis_win(b, va, n):
    o = b.off(va)
    return [f'{i.mnemonic} {i.op_str}' for i in D.disasm(b.data[o:o + n * 4], va)][:n]


def word(b, va):
    return b.u32(va)


def movz_imm(w):
    """movz wD,#imm16 (hw=0) -> (imm, rd) иначе None."""
    if (w & 0x7f800000) == 0x52800000 and ((w >> 21) & 3) == 0:
        return ((w >> 5) & 0xffff, w & 0x1f)
    return None


def find_seq(b, pred, span=8):
    """Все VA, где pred(список из span инструкций) истинно."""
    out = []
    data, base = b.data, b.base
    for o in range(0, len(data) - 4 * span, 4):
        ws = struct.unpack_from('<%dI' % span, data, o)
        if pred(ws):
            out.append(base + o)
    return out


def s1_flag_store(b):
    """cmp wN,#0x411 ; cset wM,eq ; str wM,[sp,#imm]  (флаг lens==0x411)."""
    def p(ws):
        w0, w1, w2 = ws[0], ws[1], ws[2]
        if (w0 & 0xffc00000) != 0x71000000 or ((w0 >> 10) & 0xfff) != 0x411:
            return False
        # cset wM,eq = csinc wM,wzr,wzr,ne (0x1a9f07e0 | rd)
        if (w1 & 0xffffffe0) != 0x1a9f17e0:
            return False
        if (w2 & 0xffc00000) != 0xb9000000:  # str wM,[sp,#imm]
            return False
        rn = (w2 >> 5) & 0x1f
        return rn == 31
    return find_seq(b, p)


def s1_flag_store_head(b):
    """cmp w1,#0x411 ; cset wM,eq  в самом начале функции (sibling-конструктор)."""
    def p(ws):
        w0, w1 = ws[0], ws[1]
        rd0 = (w0 >> 5) & 0x1f
        if (w0 & 0xffc00000) != 0x71000000 or ((w0 >> 10) & 0xfff) != 0x411:
            return False
        if rd0 != 1:  # w1
            return False
        return (w1 & 0x7ffffc00) == 0x1a9f0400
    return find_seq(b, p, span=2)


def s2_new_const(b):
    """movz w0,#0xe4 ; ldr x1,[sp,#..] ; strh w0,[x1,#0xa0] ; movz w19,#0x8c."""
    def p(ws):
        m = movz_imm(ws[0])
        if not m or m != (0xe4, 0):
            return False
        if (ws[1] & 0xffc00000) != 0xf9400000:  # ldr x1,[sp,#imm]
            return False
        if (ws[2] & 0xffc00000) != 0x79000000:  # strh w0,[xN,#imm]
            return False
        if ((ws[2] >> 10) & 0xfff) != 0x50:
            return False
        m2 = movz_imm(ws[3])
        return m2 == (0x8c, 19)
    return find_seq(b, p, span=4)


def s2_new_fallback(b):
    """ldr x0,[sp,#..] ; strh wzr,[x0,#0xa0] ; movz w19,#0x80  (ветка «не 0x411»)."""
    def p(ws):
        if (ws[0] & 0xffc00000) != 0xf9400000:
            return False
        if ws[1] != 0x7901401f:  # strh wzr,[x0,#0xa0]  (x0 - rn=0, imm=0xa0)
            return False
        return movz_imm(ws[2]) == (0x80, 19)
    return find_seq(b, p, span=3)


def s3_old_value(b):
    """movz w0,#0x1dba в пределах 2 инструкций от strh w0,[x1,#0xa0]."""
    out = []
    data, base = b.data, b.base
    for o in range(0, len(data) - 1, 4):
        w = struct.unpack_from('<I', data, o)[0]
        if movz_imm(w) == (0x1dba, 0):
            for k in (1, 2, 3, 4):
                w2 = struct.unpack_from('<I', data, o + 4 * k)[0]
                if (w2 & 0xffc00000) == 0x79000000 and ((w2 >> 10) & 0xfff) == 0x50 \
                        and (w2 & 0x1f) == 0:
                    out.append(base + o)
                    break
    return out


def s4_old_step(b):
    """movz w0,#0x1db3 ; ... ; and w19,w0,#0xff."""
    out = []
    data, base = b.data, b.base
    for o in range(0, len(data) - 3, 4):
        if movz_imm(struct.unpack_from('<I', data, o)[0]) == (0x1db3, 0):
            for k in range(1, 4):
                w2 = struct.unpack_from('<I', data, o + 4 * k)[0]
                # and w19,w0,#0xff = 0x12001c13
                if w2 == 0x12001c13:
                    out.append(base + o)
                    break
    return out


def s5_flag_read(b):
    """ldr wN,[xN,#0x50] ; cbz wN,<addr>."""
    out = []
    data, base = b.data, b.base
    for o in range(0, len(data) - 8, 4):
        w, w2 = struct.unpack_from('<2I', data, o)
        if (w & 0xffc00000) != 0xb9400000:
            continue
        if ((w >> 10) & 0xfff) != 0x14:
            continue
        rt = w & 0x1f
        if (w2 & 0x7f000000) != 0x34000000:  # cbz w
            continue
        if (w2 & 0x1f) != rt:
            continue
        out.append(base + o)
    return out


def s6_helper(b):
    """movz w0,#0x205c и movz w0,#0x205e в одной функции (helper ND/TELE)."""
    a, c = [], []
    data, base = b.data, b.base
    for o in range(0, len(data) - 3, 4):
        w = struct.unpack_from('<I', data, o)[0]
        m = movz_imm(w)
        if m == (0x205c, 0):
            a.append(base + o)
        elif m == (0x205e, 0):
            c.append(base + o)
    pairs = []
    for x in a:
        for y in c:
            if abs(x - y) < 0x200:
                pairs.append((x, y))
    return pairs


def report():
    res = {}
    for m in MODELS:
        for s in ('old', 'new'):
            b = load(m, s, 1)
            r = {
                'block': 'b1', 'base': hex(b.base), 'version': b.version,
                'cmp411_cset_store': [hex(x) for x in s1_flag_store(b)],
                'cmp411_cset_head': [hex(x) for x in s1_flag_store_head(b)],
                'new_const_0xe4': [hex(x) for x in s2_new_const(b)],
                'new_fallback_0x80': [hex(x) for x in s2_new_fallback(b)],
                'old_out_a0_0x1dba': [hex(x) for x in s3_old_value(b)],
                'old_step_0x1db3': [hex(x) for x in s4_old_step(b)],
                'flag_read_0x50': [hex(x) for x in s5_flag_read(b)],
                'helper_nd_tele': [[hex(x), hex(y)] for x, y in s6_helper(b)],
            }
            res[f'{m} {s}'] = r
    return res


if __name__ == '__main__':
    r = report()
    for k, v in r.items():
        print('####', k)
        for a, b in v.items():
            if a in ('block', 'base', 'version'):
                continue
            if b:
                print('   %-20s %s' % (a, b))
    if '--json' in sys.argv:
        (HERE / 'b1_sites.json').write_text(
            json.dumps(r, indent=1, ensure_ascii=False), encoding='utf8')
        print('saved b1_sites.json')
