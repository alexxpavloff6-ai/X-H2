# -*- coding: utf-8 -*-
"""Q3 шаг 10: гипотеза — сервисный модуль = префикс[0x60000..0x80000], VA=off-0x20000."""
import sys
from pathlib import Path

HERE = Path(__file__).resolve().parent
sys.path.insert(0, str(HERE))
from q3common import prefix, dis  # noqa: E402

p = prefix()
out = []
for name, va in (('resolver', 0x5460C), ('dispatcher', 0x4A458), ('logger', 0x57670), ('scalar', 0x50D94)):
    off = va + 0x20000
    out.append(f'=== {name} VA {va:#x} -> prefix off {off:#x} ===')
    out.append(dis(p, off, 20))
    out.append('')
text = '\n'.join(out)
(HERE / 'гипотеза_регион2.txt').write_text(text + '\n', encoding='utf-8')
print(text)
