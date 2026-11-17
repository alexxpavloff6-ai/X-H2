# -*- coding: utf-8 -*-
"""Q3 шаг 3: резолвер записей 0x5460C и скалярный 0x50D94 в блоке 2 (base 0)."""
import sys
from pathlib import Path

HERE = Path(__file__).resolve().parent
sys.path.insert(0, str(HERE.parents[1] / 'Сравнение_версий_2026-11-16'))
from fwcommon import load, dis  # noqa: E402

b2 = load('X-H2', 'old', 2)
out = []
for name, va, n in (('резолвер_0x5460C', 0x5460C, 120),
                    ('скаляр_резолвер_0x50D94', 0x50D94, 80),
                    ('0x51640', 0x51640, 40),
                    ('логгер_0x57670', 0x57670, 30)):
    out.append(f'=== block2: {name} ===')
    out.append(dis(b2, va, n))
    out.append('')
text = '\n'.join(out)
(HERE / 'резолвер.txt').write_text(text + '\n', encoding='utf-8')
print(text)
