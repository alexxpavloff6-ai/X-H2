# -*- coding: utf-8 -*-
"""Шаг 21 (VM): проверить направление ветвлений `cmp/ccmp/b.ne` в apply1/apply2.

Эмулируются только реальные инструкции развилки (без вызовов):
  apply1 (X-H2 new): 0x3104754  -> ветка 0x3104760 (fall-through) или 0x31048d0
  apply2 (X-H2 new): 0x3104c5c  -> ветка 0x3104c68 (bl F) или 0x3104c8c
Вход: w2 = flag, x1 = p (0 или ненулевой). Смотрим, какой адрес исполнился первым.
Это проверяет трактовку `ccmp x1,#0,#4,eq`: при flag==0 флаги = 4 (Z=1) => b.ne НЕ
переходит; при flag!=0 сравнивается x1 с 0.
"""
import sys, os, struct
sys.path.insert(0, r'<корень проекта>\Анализ_прошивки\Сравнение_версий_2026-11-16')
from fwcommon import *  # noqa
from unicorn import Uc, UC_ARCH_ARM64, UC_MODE_LITTLE_ENDIAN, UC_HOOK_CODE, UC_PROT_ALL
from unicorn.arm64_const import (UC_ARM64_REG_X0, UC_ARM64_REG_X1,
                                 UC_ARM64_REG_PC)

PAGE = 0x1000


def run_case(start, stop_a, stop_b, flag, p_nonnull):
    b = load('X-H2', 'new', 1)
    mu = Uc(UC_ARCH_ARM64, UC_MODE_LITTLE_ENDIAN)
    lo = start & ~0xfff
    hi = (max(stop_a, stop_b) + 0x1000) & ~0xfff
    mu.mem_map(lo, hi - lo, UC_PROT_ALL)
    off = lo - b.base
    mu.mem_write(lo, b.data[off:off + hi - lo])
    mu.reg_write(UC_ARM64_REG_X1, 0x4d000000 if p_nonnull else 0)
    # w2 = flag (запись в x2 младших 32 бит достаточно)
    mu.reg_write(UC_ARM64_REG_X0, 0)
    import unicorn.arm64_const as u
    mu.reg_write(u.UC_ARM64_REG_X2, flag)

    hit = {'at': None}

    def hook(mu, addr, size, ud):
        if addr in (stop_a, stop_b):
            hit['at'] = addr
            mu.emu_stop()

    mu.hook_add(UC_HOOK_CODE, hook)
    err = None
    try:
        mu.emu_start(start, 0xffffffff, count=64)
    except Exception as e:  # noqa
        err = str(e)
    return hit['at'], err


if __name__ == '__main__':
    print('apply1 (0x3104754): fall-through 0x3104760 / ветка 0x31048d0')
    for flag in (0, 1):
        for pn in (1, 0):
            a, err = run_case(0x3104754, 0x3104760, 0x31048d0, flag, pn)
            print(f'  flag={flag} p={"!=0" if pn else "==0"} -> '
                  f'{"ветка 0x31048d0 (flush-заглушки)" if a == 0x31048d0 else "fall-through 0x3104760"} '
                  f'{err or ""}')
    print('apply2 (0x3104c5c): 0x3104c68 (bl MOVDC) / ветка 0x3104c8c (заглушки -> b 0x3104c68)')
    for flag in (0, 1):
        for pn in (1, 0):
            a, err = run_case(0x3104c5c, 0x3104c68, 0x3104c8c, flag, pn)
            print(f'  flag={flag} p={"!=0" if pn else "==0"} -> '
                  f'{"ветка 0x3104c8c (заглушки, затем b 0x3104c68 -> bl MOVDC)" if a == 0x3104c8c else "прямо 0x3104c68 (bl MOVDC)"} '
                  f'{err or ""}')
