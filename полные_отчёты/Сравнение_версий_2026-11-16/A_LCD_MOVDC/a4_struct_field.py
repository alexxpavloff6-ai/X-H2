# -*- coding: utf-8 -*-
"""Шаг 4: поиск обращений через базу структуры (adrp+add+ldr/str [xN,#off]).

Флаг — поле структуры: X-H2 base 0x4c2fad8 (+0x43c), X-H2S base 0x4ba8ad8 (+0x434).
Для X-T5 база/смещение неизвестны — ищем любые LDR/STR с offset 0x434/0x43c
и смотрим, каким adrp+add получена база.

Метод: префильтр по маске load/store (unsigned offset), затем capstone только
для кандидатов, затем 8 инструкций контекста.
"""
import sys, os, json
sys.path.insert(0, r'<корень проекта>\Анализ_прошивки\Сравнение_версий_2026-11-16')
from fwcommon import *  # noqa

HERE = os.path.dirname(os.path.abspath(__file__))
OFFS = [0x434, 0x43c, 0x2c4]

WORD_CHUNK = 1 << 20


def find_ls_off(b, byte_off):
    """Все LDR/STR (unsigned offset) с точным байтовым смещением byte_off."""
    out = []
    data, base = b.data, b.base
    n = len(data) - 3
    # unsigned-offset load/store: (w & 0x3b000000) == 0x39000000
    for o in range(0, n, 4):
        w = struct.unpack_from('<I', data, o)[0]
        if (w & 0x3b000000) != 0x39000000:
            continue
        size = w >> 30
        imm12 = (w >> 10) & 0xfff
        if (imm12 << size) == byte_off:
            out.append((base + o, w))
    return out


def decode_one(b, va):
    return insns(b, va, 1)


def ctx(b, va, before=8, after=4):
    return dis(b, va - before * 4, before + after)


def main():
    res = {}
    for m in MODELS:
        for st in ('old', 'new'):
            b = load(m, st, 1)
            for off in OFFS:
                hits = find_ls_off(b, off)
                rows = []
                for va, w in hits:
                    lines = ctx(b, va).splitlines()
                    rows.append({'va': hex(va), 'ctx': lines})
                res[f'{m} {st} +{off:#x} b1'] = rows
                print(f'{m} {st} b1 off={off:#x}: {len(hits)} hits')
    open(os.path.join(HERE, 'struct_field_hits.json'), 'w', encoding='utf8').write(
        json.dumps(res, ensure_ascii=False, indent=1))


if __name__ == '__main__':
    main()
