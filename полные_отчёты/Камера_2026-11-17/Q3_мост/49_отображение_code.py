# -*- coding: utf-8 -*-
"""Q3 4-й круг, шаг 49: отображение выдержка->code (блок1 0x2EED878 / 0x2EEE118)."""
import sys
from pathlib import Path

HERE = Path(__file__).resolve().parent
sys.path.insert(0, str(HERE))
from q3common import load, dis  # noqa: E402

b1 = load('X-H2', 'old', 1)
out = []
out.append('===== block1 0x2EED878 (писатель inner[0x784], jump-table?) =====')
out.append(dis(b1, 0x2EED878, 80))
out.append('')
out.append('===== block1 0x2EEE118 (писатель w19 -> inner[0x784]) =====')
out.append(dis(b1, 0x2EEE118, 70))
text = '\n'.join(out)
(HERE / '4круг_отображение_code.txt').write_text(text + '\n', encoding='utf-8')
print(text[:12000])
