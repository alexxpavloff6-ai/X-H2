# -*- coding: utf-8 -*-
"""Q3 2-й круг, шаг 32: условие дефекта 0x30256EC (флаг=1) и гейты 0x2FE18DC/0x2FD8DE0/0x2FD8DBC."""
import sys
from pathlib import Path

HERE = Path(__file__).resolve().parent
sys.path.insert(0, str(HERE))
from q3common import load, dis  # noqa: E402

b1 = load('X-H2', 'old', 1)
out = []
for name, va, n in (('УСЛОВИЕ 0x30256EC (флаг=1)', 0x30256EC, 180),
                    ('гейт A 0x2FE18DC', 0x2FE18DC, 50),
                    ('гейт B 0x2FD8DE0', 0x2FD8DE0, 40),
                    ('ctx 0x2FD8DBC', 0x2FD8DBC, 25)):
    out.append(f'===== {name} =====')
    out.append(dis(b1, va, n))
    out.append('')
text = '\n'.join(out)
(HERE / '2круг_УСЛОВИЕ_ДЕФЕКТА.txt').write_text(text + '\n', encoding='utf-8')
print(text[:13000])
