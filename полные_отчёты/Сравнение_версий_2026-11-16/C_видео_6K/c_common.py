# -*- coding: utf-8 -*-
"""Локальный хелпер для задачи C (видео 6.2K+).

fwcommon.adrp_sites сравнивает цель ADRP (знаковое число) со страницей,
заданной как 0xffffffff...; в Python это разные int, поэтому для страниц
с отрицательным смещением (глобальные структуры ДО кода модуля) поиск
не работает. Здесь ADRP-цель нормализуется к 64-битному беззнаковому виду.

Все функции только читают блоки прошивки.
"""
import sys, struct, re
sys.path.insert(0, r'<корень проекта>\Анализ_прошивки\Сравнение_версий_2026-11-16')
from fwcommon import (load, dis, insns, find_bytes, func_start, string_refs,
                      bl_callers, iter_words, MODELS, cs)  # noqa

M64 = (1 << 64) - 1


def u64(x):
    return x & M64


def adrp_target64(word, pc):
    if (word & 0x9f000000) != 0x90000000:
        return None
    immlo = (word >> 29) & 3
    immhi = (word >> 5) & 0x7ffff
    imm = (immhi << 2) | immlo
    if imm & (1 << 20):
        imm -= 1 << 21
    return u64((pc & ~0xfff) + (imm << 12)), word & 31


def adrp_sites64(b, page):
    """Все ADRP, чья цель равна page (с точностью до страницы)."""
    page = u64(page) & ~0xfff
    out = []
    for va, w in iter_words(b):
        t = adrp_target64(w, va)
        if t and (t[0] & ~0xfff) == page:
            out.append((va, t[1]))
    return out


MEMOPS = ('ldr', 'ldrb', 'ldrh', 'ldrsb', 'ldrsh', 'ldur', 'ldurb',
          'str', 'strb', 'strh', 'stur', 'sturb', 'ldp', 'stp')


def base_refs(b, page, base, span=24):
    """Все LDR/STR [xN,#imm] после ADRP(page)+ADD(base).

    Возвращает список dict(site, field, rel, insn, kind) где field — смещение
    от начала страницы (может быть отрицательным), rel — от базы base.
    """
    page = u64(page) & ~0xfff
    out = []
    for va, reg in adrp_sites64(b, page):
        r = f'x{reg}'
        cur = None
        for x in insns(b, va + 4, span):
            ops = [p.strip() for p in x.op_str.split(',')]
            if x.mnemonic == 'add' and len(ops) == 3 and ops[0] == r and ops[1] == r:
                imm = int(ops[2].lstrip('#'), 0)
                cur = imm if cur is None else cur + imm
                if cur > 0x100000:   # ушли из структуры
                    break
                continue
            if x.mnemonic in MEMOPS and f'[{r}' in x.op_str:
                m = re.search(r'#(-?0x[0-9a-f]+|-?\d+)', x.op_str)
                imm = int(m.group(1), 0) if m else 0
                # парный ldp/stp: второй регистр-приёмник не интересен
                field = u64(page) + (cur or 0) + imm
                rel = (cur or 0) + imm - base
                out.append({'site': x.address, 'field': field, 'rel': rel,
                            'insn': f'{x.address:x}: {x.mnemonic} {x.op_str}',
                            'kind': x.mnemonic})
                if ops and ops[0] == r:   # база перезаписана загрузкой
                    break
                continue
            if x.mnemonic in ('bl', 'b', 'ret', 'br', 'blr', 'cbz', 'cbnz', 'tbz', 'tbnz',
                              'adrp', 'mov', 'madd', 'mul'):
                break
    return out


def find_state_base(b, prepare_va, span=60):
    """(page, base) структуры состояния из кода prepare-функции."""
    for x in insns(b, prepare_va, span):
        if x.mnemonic == 'adrp':
            page = int(x.op_str.split('#')[1], 0)
            reg = x.op_str.split(',')[0]
            for y in insns(b, x.address + 4, 4):
                p = [t.strip() for t in y.op_str.split(',')]
                if y.mnemonic == 'add' and len(p) == 3 and p[0] == reg and p[1] == reg:
                    return u64(page), int(p[2].lstrip('#'), 0)
            return u64(page), None
    return None, None
