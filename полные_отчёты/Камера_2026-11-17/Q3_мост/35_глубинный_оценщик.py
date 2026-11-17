# -*- coding: utf-8 -*-
"""Q3 2-й круг, шаг 35: глубинный оценщик 0x2F85F3C и полевые геттеры (блок 0)."""
import sys
from pathlib import Path

HERE = Path(__file__).resolve().parent
sys.path.insert(0, str(HERE))
from q3common import load, dis  # noqa: E402

b0 = load('X-H2', 'old', 0)
b1 = load('X-H2', 'old', 1)
out = []
out.append('===== ГЛУБИННЫЙ ОЦЕНЩИК 0x2F85F3C (==2 -> флаг) =====')
out.append(dis(b1, 0x2F85F3C, 150))
out.append('')
for name, va in (('fieldA 0x1561D8C (getter0, must==1)', 0x1561D8C),
                 ('fieldB 0x1561DB0 (getter2)', 0x1561DB0),
                 ('fieldC 0x1563D20 (getter3)', 0x1563D20),
                 ('fieldD 0x15632EC (getter5)', 0x15632EC)):
    out.append(f'===== {name} (block0) =====')
    out.append(dis(b0, va, 14))
    out.append('')
text = '\n'.join(out)
(HERE / '2круг_глубинный_оценщик.txt').write_text(text + '\n', encoding='utf-8')
print(text[:11000])
