# -*- coding: utf-8 -*-
"""Q3 шаг 12: дизасм ключевых кандидатов условия дефекта."""
import sys
from pathlib import Path

HERE = Path(__file__).resolve().parent
sys.path.insert(0, str(HERE))
from q3common import load, dis  # noqa: E402

b0 = load('X-H2', 'old', 0)
b1 = load('X-H2', 'old', 1)
out = []
for name, b, va, n in (
    ('block0 0x113D9E0 (CH+REC_VIEW+SHUTTER_TYPE+SPEED)', b0, 0x113D9E0, 220),
    ('block1 0x2BD5114 (DOTLCD outputs)', b1, 0x2BD5114, 200),
    ('block0 property API 0x14D1B20', b0, 0x14D1B20, 40),
):
    out.append(f'===== {name} =====')
    out.append(dis(b, va, n))
    out.append('')
text = '\n'.join(out)
(HERE / 'кандидаты_условия.txt').write_text(text + '\n', encoding='utf-8')
print(text[:12000])
