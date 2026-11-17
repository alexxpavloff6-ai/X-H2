# -*- coding: utf-8 -*-
"""Q3 шаг 20: характеристика кандидатов 0x12DA08C и 0x2C88E98."""
import sys
from pathlib import Path

HERE = Path(__file__).resolve().parent
sys.path.insert(0, str(HERE))
from q3common import load, dis  # noqa: E402

b0 = load('X-H2', 'old', 0)
b1 = load('X-H2', 'old', 1)
out = []
for name, b, va, n in (('block0 0x12DA08C (CONT+SPEED_M+SHUTTER_TYPE)', b0, 0x12DA08C, 110),
                       ('block1 0x2C88E98 (CONT+REC_VIEW)', b1, 0x2C88E98, 70)):
    out.append(f'===== {name} =====')
    out.append(dis(b, va, n))
    out.append('')
text = '\n'.join(out)
(HERE / 'кандидаты_2.txt').write_text(text + '\n', encoding='utf-8')
print(text[:9000])
