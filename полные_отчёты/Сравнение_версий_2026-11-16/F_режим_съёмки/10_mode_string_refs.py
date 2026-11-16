"""F: как связаны строки MODE_RECORD_* и коды.

Ищем:
  * ADRP+ADD ссылки на адреса строк 0x1640d..0x1641...;
  * u64-массивы указателей на эти строки (таблица указателей);
  * рядом с таблицей — массив кодов/индексов.
"""
import sys, re, json, struct, collections
sys.path.insert(0, r'<корень проекта>\Анализ_прошивки\Сравнение_версий_2026-11-16')
from fwcommon import *
import fwcommon

b0 = load('X-H2', 'new', 0)
B1 = load('X-H2', 'new', 1)

# 1) границы блока строк MODE_RECORD_*
start = 0x1640db0
o = b0.off(start)
# идём до конца серии строк
end = start
while True:
    z = b0.data.find(b'\x00', b0.off(end))
    end = b0.base + z + 1
    s = b0.cstr(end)
    if not s or not s.startswith(('MODE_', 'DRIVE', 'BKT', 'DR_', 'SP_', 'ADV_', 'REC_')):
        break
print(f'строки MODE_*: {start:#x}..{end:#x}')

# 2) u64-указатели на этот диапазон в блоке 0/1
for b in (b0, B1):
    hits = []
    for va, w in iter_words(b):
        if w == 0 and va % 4 == 0:
            continue
    # ищем u64 по 8-байтовой сетке
    data, base = b.data, b.base
    for off in range(0, len(data) - 7, 8):
        v = struct.unpack_from('<Q', data, off)[0]
        if start <= v < end:
            hits.append(base + off)
    print(f'{b}: u64-указателей на строки MODE_*: {len(hits)}')
    if hits:
        print('   первые:', [hex(h) for h in hits[:10]], '... последние:', [hex(h) for h in hits[-5:]])
        # показываем окрестность первой таблицы: 8 указателей до/после
        h = hits[0]
        for k in range(-8, 24):
            va = h + k * 8
            try:
                v = b.u64(va)
            except Exception:
                break
            s = b.cstr(v) if b.base <= v < b.end else None
            print(f'   {va:#x}: {v:#018x}  {s or ""}')

# 3) ADRP+ADD ссылки на эти строки в коде
def adrp_add_refs(b, targets):
    res = collections.defaultdict(list)
    for va, w in iter_words(b):
        if (w & 0x9f000000) != 0x90000000:
            continue
        t = fwcommon._adrp_target(w, va)
        if not t:
            continue
        page, reg = t
        r = f'x{reg}'
        for x in insns(b, va + 4, 3):
            m = re.fullmatch(r'(x\d+), (x\d+), #(-?0x[0-9a-f]+|-?\d+)', x.op_str)
            if x.mnemonic == 'add' and m and m.group(2) == r:
                tgt = page + int(m.group(3), 0)
                if tgt in targets:
                    res[tgt].append(x.address)
                break
    return res

targets = set()
for a in range(start, end, 1):
    s = b0.cstr(a)
    if s:
        targets.add(a)
refs = adrp_add_refs(b0, targets)
print(f'\nADRP+ADD на строки MODE_* в b0: {sum(len(v) for v in refs.values())} шт, '
      f'{len(refs)} разных строк')
addrs = sorted(a for v in refs.values() for a in v)
print('   адреса ref-сайтов:', [hex(a) for a in addrs[:40]])
