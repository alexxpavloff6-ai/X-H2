# -*- coding: utf-8 -*-
"""D3: структура params (x19 функции подготовки кадра 0x2ce8f3c) — кто её создаёт,
чем очищает, куда передаёт; ищем чтения +0x60.

X-H2 5.33:
  - prep 0x2ce8f3c вызывается из 0x2dd1bb0 (recfCalcRecifParam) в 0x2dd219c:
        x1 = x20 (params), x2 = sp+0xd0 (commit)
  - рядом (0x2dd1f70) видно memset(x20, 0, 0x68) и memset(sp+0xd0, 0, 0xcc):
        значит params = 0x68 байт, commit = 0xcc байт
Скрипт печатает пролог/эпилог 0x2dd1bb0, откуда берётся x20, и все чтения [x?,#0x60]
в этой функции и в вызываемых ею функциях.
"""
import sys, re
sys.path.insert(0, r'<корень проекта>\Анализ_прошивки\Сравнение_версий_2026-11-16\D_брекетинг')
from dhelp import *  # noqa

model, state = 'X-H2', 'new'
b = load(model, state, 1)
print('=== пролог 0x2dd1bb0 ===')
print(dis(b, 0x2dd1bb0, 40))
print('\n=== memset-ы перед подготовкой (0x2dd1f40..0x2dd1fc0) ===')
print(dis(b, 0x2dd1f40, 40))
