# -*- coding: utf-8 -*-
"""Q3 шаг 5: резолвер/диспетчер/логгер в префиксе DAT (база 0)."""
import sys
from pathlib import Path

HERE = Path(__file__).resolve().parent
sys.path.insert(0, str(HERE))
from q3common import prefix, dis  # noqa: E402

p = prefix()
print(repr(p))
out = []
for name, va, n in (('резолвер_0x5460C', 0x5460C, 80),
                    ('диспетчер_0x4A458', 0x4A458, 120),
                    ('логгер_0x57670', 0x57670, 40),
                    ('скаляр_0x50D94', 0x50D94, 40)):
    out.append(f'=== prefix: {name} ===')
    out.append(dis(p, va, n))
    out.append('')
text = '\n'.join(out)
(HERE / 'префикс_сервисы.txt').write_text(text + '\n', encoding='utf-8')
print(text)
