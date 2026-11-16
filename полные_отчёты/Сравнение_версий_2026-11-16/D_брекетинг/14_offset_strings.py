# -*- coding: utf-8 -*-
"""D: строки отладки "[OFFSET] ..." в блоке 1 (X-H2 new/old). Это имена/теги
параметров в логе функции подготовки кадра; могут назвать группу 0x1915x.
Декодируем Shift-JIS (японский) с заменами и печатаем адреса.
"""
import sys, re
sys.path.insert(0, r'<корень проекта>\Анализ_прошивки\Сравнение_версий_2026-11-16\D_брекетинг')
from dhelp import *  # noqa

for m, st, idx in (('X-H2', 'new', 1), ('X-H2', 'old', 1)):
    b = load(m, st, idx)
    print(f'===== {m} {st} b{idx}')
    for mm in re.finditer(rb'\[OFFSET\]', b.data):
        a = b.base + mm.start()
        raw = b.data[mm.start():mm.start() + 72].split(b'\x00')[0]
        for enc in ('shift_jis', 'cp932'):
            try:
                s = raw.decode(enc)
                break
            except Exception:
                s = None
        print(f'{a:#x} latin1={raw.decode("latin1")!r}')
        if s:
            print(f'         sjis  ={s!r}')
