# -*- coding: utf-8 -*-
"""Q3 шаг 16: функция 0x311A2xx (трогает current 0x4C3F1F8) и построитель params 0x31053xx."""
import sys
from pathlib import Path

HERE = Path(__file__).resolve().parent
sys.path.insert(0, str(HERE))
from q3common import load, dis, func_start  # noqa: E402

b1 = load('X-H2', 'old', 1)
print('func_start(0x311A248) =', hex(func_start(b1, 0x311A248) or 0))
print('func_start(0x31054E8) =', hex(func_start(b1, 0x31054E8) or 0))
out = []
for name, va, n in (('block1 0x311A1C0 (current container)', 0x311A1C0, 130),
                    ('block1 0x3105300 (params build)', 0x3105300, 170)):
    out.append(f'===== {name} =====')
    out.append(dis(b1, va, n))
    out.append('')
text = '\n'.join(out)
(HERE / 'params_писатели.txt').write_text(text + '\n', encoding='utf-8')
print(text[:11000])
