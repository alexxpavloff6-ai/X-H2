"""F: строки "rec"/"drive"/"still"/"movie" в b1 и их использование.

S+0x2c (0x244eb4c) используется как char-буфер (strcpy/strlen/0x2ec0ef0).
Гипотеза: там лежит имя режима. Ищем литералы и сравнения.
"""
import sys, re, json, struct, collections
sys.path.insert(0, r'<корень проекта>\Анализ_прошивки\Сравнение_версий_2026-11-16')
from fwcommon import *
import fwcommon

b = load('X-H2', 'new', 1)


def find_strings(b, words):
    res = []
    for w in words:
        needle = w.encode() + b'\x00'
        start = 0
        while True:
            i = b.data.find(needle, start)
            if i < 0:
                break
            va = b.base + i
            # проверим, что слева 0 (начало строки) или не печатный
            if i == 0 or b.data[i - 1] < 32:
                res.append((va, w))
            start = i + 1
    return res


words = ['rec', 'drive', 'still', 'movie', 'STILL', 'MOVIE', 'REC', 'DRIVE']
hits = find_strings(b, words)
for va, w in hits:
    print(f'{va:#x}: "{w}"')

# ссылки adrp+add на эти адреса + окрестность
targets = {va for va, _ in hits}
refs = collections.defaultdict(list)
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
                refs[tgt].append(x.address)
            break

print('\n-- ссылки --')
for tgt, sites in sorted(refs.items()):
    print(f'{tgt:#x} "{b.cstr(tgt)}": {[hex(s) for s in sites]}')
    for s in sites[:4]:
        print('   ', dis(b, max(b.base, s - 24), 12).replace('\n', '\n    '))
