# -*- coding: utf-8 -*-
"""Q3 2-й круг, шаг 34: финальный оценщик 0x2F84C48, drive-getter 0x3024664,
полевые геттеры struct 0x2748 (0x1561D8C/0x1561DB0/0x1563D20/0x15632EC)."""
import sys
from pathlib import Path

HERE = Path(__file__).resolve().parent
sys.path.insert(0, str(HERE))
from q3common import load, dis  # noqa: E402

b1 = load('X-H2', 'old', 1)
out = []
for name, va, n in (('ФИНАЛЬНЫЙ ОЦЕНЩИК 0x2F84C48', 0x2F84C48, 160),
                    ('drive-getter 0x3024664', 0x3024664, 30),
                    ('fieldA 0x1561D8C (getter0)', 0x1561D8C, 16),
                    ('fieldB 0x1561DB0 (getter2)', 0x1561DB0, 16),
                    ('fieldC 0x1563D20 (getter3)', 0x1563D20, 16),
                    ('fieldD 0x15632EC (getter5)', 0x15632EC, 16)):
    out.append(f'===== {name} =====')
    out.append(dis(b1, va, n))
    out.append('')
text = '\n'.join(out)
(HERE / '2круг_ФИНАЛЬНЫЙ_ОЦЕНЩИК.txt').write_text(text + '\n', encoding='utf-8')
print(text[:12000])
