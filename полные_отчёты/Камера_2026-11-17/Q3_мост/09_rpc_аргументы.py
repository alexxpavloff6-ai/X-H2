# -*- coding: utf-8 -*-
"""Q3 шаг 9: аргументы 11 вызовов RPC-враппера 0x14CF45C (id=w0, buf=x2).
Ищем id=0x4C и вообще какие id публикуются через сервис."""
import sys
from pathlib import Path

HERE = Path(__file__).resolve().parent
sys.path.insert(0, str(HERE))
from q3common import load, dis, bl_callers, insns  # noqa: E402

b0 = load('X-H2', 'old', 0)
sites = [s for s, k in bl_callers(b0, 0x14CF45C)]
out = []
for s in sites:
    out.append(f'===== вызов RPC-враппера @ {s:#x} =====')
    out.append(dis(b0, s - 0x40, 17))
    out.append('')
text = '\n'.join(out)
(HERE / 'rpc_вызовы.txt').write_text(text + '\n', encoding='utf-8')
print(text)
