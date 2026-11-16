"""G2: общие функции поиска образа Cortex-M4 в update.dat (только чтение).

DAT закодирован побитовой инверсией (XOR 0xFF) целиком; FFLZ-блоки распаковываются
функцией unpack_fflz из `анализ_файла.py` (MIT, tiredboffin/fffw).

Модуль намеренно без побочных эффектов: ничего не пишет, только читает.
"""
from __future__ import annotations
import array
import importlib.util
import json
import math
import struct
import sys
from pathlib import Path

ROOT = Path(r'<корень проекта>')
HERE = Path(__file__).resolve().parent
ANALYSIS = ROOT / 'Анализ_прошивки'
TOOLS = ANALYSIS / 'инструменты'
sys.path.insert(0, str(TOOLS))

DAT_NEW = ROOT / 'FIRMWARE' / 'ver new' / 'FWUP0028 (2).DAT'
DAT_OLD = ROOT / 'FIRMWARE' / 'ver 5.30' / 'FWUP0028.DAT'

TRANSLATION = bytes.maketrans(bytes(range(256)), bytes(255 - i for i in range(256)))


def _load_fwbase():
    spec = importlib.util.spec_from_file_location('fwbase', ANALYSIS / 'анализ_файла.py')
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod


fwbase = _load_fwbase()
unpack_fflz = fwbase.unpack_fflz


def load_dat(path=DAT_NEW, decode=True):
    raw = Path(path).read_bytes()
    return {'path': str(path), 'raw': raw, 'dec': raw.translate(TRANSLATION) if decode else raw}


def load_block(model, state, idx):
    """Распакованный FFLZ-блок из `blocks/` через fwcommon (только чтение)."""
    global _fwcommon
    try:
        _fwcommon
    except NameError:
        sys.path.insert(0, str(ANALYSIS / 'Сравнение_версий_2026-11-16'))
        import fwcommon as _fwcommon  # noqa: F811
    return _fwcommon.load(model, state, idx)


def find_fflz(dec, step=0x1000, start=0x274):
    """Сканирует заголовки FFLZ (usize/csize/pages/page_size/align), проверяет распаковку."""
    out = []
    n = len(dec)
    for off in range(start, n - 20, step):
        usize, csize, pages, page_size, align = struct.unpack_from('<5I', dec, off)
        if not (0x10000 < usize < 0x10000000 and 0x1000 < csize <= usize and off + csize <= n):
            continue
        if page_size not in (0x1000, 0x2000, 0x4000, 0x8000, 0x10000):
            continue
        try:
            block = unpack_fflz(dec, off)
        except Exception:
            continue
        out.append({'off': off, 'usize': usize, 'csize': csize, 'pages': pages,
                    'page_size': page_size, 'align': align, 'data': block})
    return out


def regions(n, blocks, tail_guard=72):
    """Непокрытые FFLZ области файла: [(start, end, имя)]."""
    spans = sorted((b['off'], b['off'] + b['csize'], f"fflz@{b['off']:#x}") for b in blocks)
    out, pos = [], 0
    for s, e, name in spans:
        if s > pos:
            out.append((pos, s, 'raw'))
        pos = max(pos, e)
    if pos < n - tail_guard:
        out.append((pos, n - tail_guard, 'raw_tail'))
    out.append((n - tail_guard, n, 'ecdsa_signature'))
    return out


# ---------------------------------------------------------------- эвристики ARMv7-M

# Диапазоны, куда может указывать начальный SP (MSP) — карта XP5 не документирована,
# поэтому набор широкий, а отбор идёт по структуре таблицы векторов.
SP_RANGES = [
    (0x00000000, 0x00040000),   # ITCM/низкая память
    (0x00200000, 0x00400000),   # OCRAM-подобная
    (0x00800000, 0x01000000),   # TCM i.MX-подобная
    (0x0C000000, 0x0D000000),
    (0x20000000, 0x20400000),   # классический SRAM Cortex-M
    (0x24000000, 0x24100000),
    (0x30000000, 0x30800000),
    (0x38000000, 0x38100000),
    (0x40000000, 0x41000000),
    (0xFA000000, 0xFB000000),   # companion-SRAM (гипотеза задачи)
]


def _plausible_sp(w):
    if w == 0 or w == 0xFFFFFFFF:
        return False
    if w & 3:
        return False
    return any(lo <= w < hi for lo, hi in SP_RANGES)


def words_of(buf, start=0, end=None):
    end = len(buf) if end is None else end
    end = min(end, len(buf)) & ~3
    start &= ~3
    a = array.array('I')
    a.frombytes(bytes(buf[start:end]))
    if sys.byteorder != 'little':
        a.byteswap()
    return a, start


def vector_candidates(words, base_va=0, min_vec=8, cluster=0x200000, max_report=200):
    """Ищет таблицы векторов Cortex-M.

    Признак: word0 — правдоподобный SP (SRAM, кратен 4), затем >= min_vec подряд
    нечётных слов-адресов, укладывающихся в окно `cluster` (код/вектора в одном регионе).
    Возвращает список кандидатов с оценкой.
    """
    out = []
    n = len(words)
    i = 0
    while i < n - min_vec - 1:
        w0 = words[i]
        if not _plausible_sp(w0):
            i += 1
            continue
        vals = []
        j = i + 1
        lo = 1 << 32
        hi = 0
        while j < n and (words[j] & 1):
            v = words[j]
            nlo, nhi = min(lo, v), max(hi, v)
            if nhi - nlo > cluster:
                break
            lo, hi = nlo, nhi
            vals.append(v)
            j += 1
            if len(vals) >= 64:
                break
        if len(vals) >= min_vec:
            uniq = len(set(vals))
            out.append({'off': base_va + 4 * i, 'sp': w0, 'nvec': len(vals),
                        'uniq': uniq, 'lo': lo, 'hi': hi, 'vecs': vals[:24]})
            i = j
        else:
            i += 1
    out.sort(key=lambda r: (-r['nvec'], -r['uniq']))
    return out[:max_report]


def thumb_stats(buf, off, length, capstone_asm=None):
    """Плотность правдоподобного Thumb-кода на участке (для отличия кода от данных)."""
    from capstone import Cs, CS_ARCH_ARM, CS_MODE_THUMB, CS_MODE_MCLASS
    cs = capstone_asm or Cs(CS_ARCH_ARM, CS_MODE_THUMB | CS_MODE_MCLASS)
    chunk = bytes(buf[off:off + length])
    total = len(chunk) // 2
    ok = pushes = bls = ldrs = 0
    for ins in cs.disasm(chunk, off):
        ok += 1
        m = ins.mnemonic
        if m in ('push', 'push.w') and 'lr' in ins.op_str:
            pushes += 1
        elif m.startswith('bl'):
            bls += 1
        elif m in ('ldr', 'ldr.w') and '[pc' in ins.op_str:
            ldrs += 1
    return {'bytes': len(chunk), 'insns': ok, 'halfwords': total,
            'density': round(ok / total, 3) if total else 0.0,
            'push_lr': pushes, 'bl': bls, 'ldr_pc': ldrs}


def entropy(buf, off, length=0x1000):
    chunk = bytes(buf[off:off + length])
    if not chunk:
        return 0.0
    c = [0] * 256
    for b in chunk:
        c[b] += 1
    e = 0.0
    for k in c:
        if k:
            p = k / len(chunk)
            e -= p * math.log2(p)
    return round(e, 3)


def printable_runs(buf, off, length=0x1000, minlen=8):
    """Доля печатных ASCII и список строк >= minlen в участке."""
    chunk = bytes(buf[off:off + length])
    runs, cur = [], bytearray()
    for b in chunk:
        if 32 <= b < 127:
            cur.append(b)
        else:
            if len(cur) >= minlen:
                runs.append(cur.decode('latin1'))
            cur = bytearray()
    if len(cur) >= minlen:
        runs.append(cur.decode('latin1'))
    return runs


# ------------------------------------------------- идиомы Thumb (быстрые байтовые метрики)

def thumb_metrics(buf, off=0, length=None):
    """Доли «характерных для ARMv7-M» образцов среди 16-битных полуслов участка.

    * push_lr — старший байт 0xB5 (push с сохранением lr) — в коде M4 частый пролог;
    * bx_lr   — полуслово 0x4770 (`bx lr`) — типичный конец функции;
    * bl      — пара (0xF0..0xF7, 0xD0.. ) — 32-битный BL;
    * ldr_pc  — 0x48..0x4F — `ldr rN,[pc,#imm]` (литеральный пул);
    * udf     — 0xDE.. — в коде ARMv7-M почти не встречается (маркер данных).
    В случайных данных push_lr ≈ 0.4 %, в реальном коде — единицы процентов.
    """
    length = len(buf) - off if length is None else min(length, len(buf) - off)
    length &= ~1
    chunk = bytes(buf[off:off + length])
    hw = length // 2
    if not hw:
        return {'bytes': 0}
    hi = chunk[1::2]                # старшие байты полуслов
    push_lr = hi.count(0xB5)
    udf = sum(hi.count(x) for x in (0xDE, 0xDF))
    ldr_pc = sum(hi.count(x) for x in range(0x48, 0x50))
    bl_hi = sum(hi.count(x) for x in range(0xF0, 0xF8))
    # BL: за первым полусловом 0xF0..0xF7 идёт полуслово с (hi & 0xD0) == 0xD0
    bl = 0
    for b0 in range(0xD0, 0x100):
        if b0 & 0xD0 != 0xD0:
            continue
        pos = chunk.find(bytes([b0]))
        while pos >= 0:
            if pos % 2 == 1 and pos >= 1 and 0xF0 <= chunk[pos - 1] <= 0xF7:
                bl += 1
            pos = chunk.find(bytes([b0]), pos + 1)
    bx_lr = 0
    pos = chunk.find(b'\x70\x47')
    while pos >= 0:
        if pos % 2 == 0:
            bx_lr += 1
        pos = chunk.find(b'\x70\x47', pos + 1)
    return {'bytes': length, 'halfwords': hw,
            'push_lr': push_lr, 'push_lr_pct': round(100 * push_lr / hw, 3),
            'bx_lr': bx_lr, 'bx_lr_pct': round(100 * bx_lr / hw, 3),
            'bl': bl, 'bl_pct': round(100 * bl / hw, 3),
            'ldr_pc_pct': round(100 * ldr_pc / hw, 3),
            'udf_pct': round(100 * udf / hw, 3),
            'code_score': round(push_lr / hw * 100 + bx_lr / hw * 100 + bl / hw * 100, 3)}


def windowed_thumb(buf, win=0x10000, start=0, end=None):
    end = len(buf) if end is None else end
    rows = []
    for off in range(start, end - 0x400, win):
        m = thumb_metrics(buf, off, min(win, end - off))
        if m['bytes']:
            m['off'] = off
            rows.append(m)
    return rows


def thumb_metrics_np(buf, off=0, length=None):
    """То же, что thumb_metrics, но на numpy (быстро и корректно для BL)."""
    import numpy as np
    length = len(buf) - off if length is None else min(length, len(buf) - off)
    length &= ~1
    if length < 4:
        return {'bytes': 0, 'halfwords': 0}
    a = np.frombuffer(bytes(buf[off:off + length]), dtype=np.uint8)
    hw = a.view('<u2')                      # halfwords, little endian
    hi = a[1::2].astype(np.uint16)          # старшие байты полуслов
    n = len(hw)
    push_lr = int(np.count_nonzero(hi == 0xB5))
    # BL: hw1 high byte 0xF0..0xF7, hw2 high byte 0xD0..0xDF или 0xF0..0xFF (11 J1 1 J2)
    bl = int(np.count_nonzero(((hi[:-1] >= 0xF0) & (hi[:-1] <= 0xF7)) &
                              ((hi[1:] & 0xD0) == 0xD0)))
    bx_lr = int(np.count_nonzero(hw == 0x4770))
    udf = int(np.count_nonzero((hw & 0xFF00) == 0xDE00))
    ldr_pc = int(np.count_nonzero((hi >= 0x48) & (hi <= 0x4F)))
    blx = int(np.count_nonzero((hw & 0xFF00) == 0x4780))
    return {'bytes': length, 'halfwords': n,
            'push_lr': push_lr, 'push_lr_pct': round(100 * push_lr / n, 3),
            'bx_lr': bx_lr, 'bx_lr_pct': round(100 * bx_lr / n, 3),
            'bl': bl, 'bl_pct': round(100 * bl / n, 3),
            'blx': blx,
            'ldr_pc_pct': round(100 * ldr_pc / n, 3),
            'udf_pct': round(100 * udf / n, 3),
            'code_score': round(100 * (bl + bx_lr) / n, 3)}


def windowed_thumb_np(buf, win=0x4000, start=0, end=None):
    end = len(buf) if end is None else end
    rows = []
    for off in range(start, end - 0x400, win):
        m = thumb_metrics_np(buf, off, min(win, end - off))
        if m.get('halfwords'):
            m['off'] = off
            rows.append(m)
    return rows


