"""F: таблица строк MODE_* и функция, которая по коду возвращает имя режима.

1) собираем все C-строки блока 0/1, начинающиеся с MODE_/DRIVE_/BKT_/DR_;
2) для каждой ищем ADRP+ADD ссылку на её адрес;
3) группируем по функциям — та, что ссылается на десятки MODE_RECORD_*, и есть
   резолвер имён.
"""
import sys, re, json, struct, collections
sys.path.insert(0, r'<корень проекта>\Анализ_прошивки\Сравнение_версий_2026-11-16')
from fwcommon import *

PAT = re.compile(rb'(MODE_[A-Z0-9_]{2,40}|DRIVE[A-Z0-9_]{0,40}|[A-Z_]{2,30}BKT[A-Z0-9_]{0,30}|DR_[A-Z0-9_]{2,30})\x00')


def strings_with_prefix(b, pat):
    out = {}
    data = b.data
    for m in pat.finditer(data):
        out[b.base + m.start()] = m.group(1).decode('latin1')
    return out


def refs_to_strings(b, targets):
    """ADRP+ADD, попадающие точно в targets -> {addr: [site...]}"""
    refs = collections.defaultdict(list)
    for va, reg in [(a, r) for a, r in _all_adrp(b)]:
        r = f'x{reg}'
        cur = None
        for x in insns(b, va + 4, 3):
            m = re.fullmatch(r'(x\d+), (x\d+), #(-?0x[0-9a-f]+|-?\d+)', x.op_str)
            if x.mnemonic == 'add' and m and m.group(2) == r:
                tgt = _adrp_val(b, va) + int(m.group(3), 0)
                if tgt in targets:
                    refs[tgt].append(x.address)
                break
    return refs


def _all_adrp(b):
    for va, w in iter_words(b):
        if (w & 0x9f000000) == 0x90000000:
            t = fwcommon._adrp_target(w, va)
            if t:
                yield va, t[1]


def _adrp_val(b, va):
    return fwcommon._adrp_target(b.u32(va), va)[0]


for idx in (0, 1):
    b = load('X-H2', 'new', idx)
    strs = strings_with_prefix(b, PAT)
    print(f'== X-H2 5.33 b{idx}: строк MODE_*/DRIVE*/BKT* {len(strs)}')
    for a, s in sorted(strs.items())[:200]:
        print(f'   {a:#x}  {s}')
