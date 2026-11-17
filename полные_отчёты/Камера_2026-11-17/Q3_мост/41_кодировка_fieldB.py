# -*- coding: utf-8 -*-
"""Q3 3-й круг, шаг 41: функция кодировки fieldB 0x14F396C (выдержка -> индекс 0..40)."""
import sys
from pathlib import Path

HERE = Path(__file__).resolve().parent
sys.path.insert(0, str(HERE))
from q3common import load, dis  # noqa: E402

b0 = load('X-H2', 'old', 0)
out = []
out.append('===== КОДИРОВКА fieldB 0x14F396C =====')
out.append(dis(b0, 0x14F396C, 90))
out.append('')
out.append('===== смежная 0x14F38A8 (field +0xAE) =====')
out.append(dis(b0, 0x14F38A8, 40))
text = '\n'.join(out)
(HERE / '3круг_кодировка_fieldB.txt').write_text(text + '\n', encoding='utf-8')
print(text)
