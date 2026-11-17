# -*- coding: utf-8 -*-
"""Q3 2-й круг, шаг 24: set_record-вход 0x4BC90, set-worker 0x4C090;
вызывающие set-пути в loader и блоках 0/1 (поиск block0 set-враппера)."""
import json
import sys
from pathlib import Path

HERE = Path(__file__).resolve().parent
sys.path.insert(0, str(HERE))
from q3common import loader, load, dis, bl_callers, func_start  # noqa: E402

L = loader()
out = []
for name, va, n in (('set_entry 0x4BC90', 0x4BC90, 110),
                    ('set_worker 0x4C090 (продолжение)', 0x4C090, 80)):
    out.append(f'===== {name} =====')
    out.append(dis(L, va, n))
    out.append('')

callers = {}
for name, tgt in (('set_entry_0x4BC90', 0x4BC90), ('set_worker_0x4C090', 0x4C090),
                  ('reg_handler_0x4BBD4', 0x4BBD4), ('resolve_worker_0x54354', 0x54354)):
    rows = []
    for src_name, b in (('loader', L), ('block0', load('X-H2', 'old', 0)), ('block1', load('X-H2', 'old', 1))):
        for s, k in bl_callers(b, tgt):
            rows.append({'src': src_name, 'site': hex(s), 'func': hex(func_start(b, s) or 0)})
    callers[name] = rows
    out.append(f'=== вызовы {name}: {len(rows)} ===')
    for r in rows:
        out.append(f"  {r['src']} {r['site']} func={r['func']}")
    out.append('')

text = '\n'.join(out)
(HERE / '2круг_set_путь.txt').write_text(text + '\n', encoding='utf-8')
(HERE / '2круг_set_вызовы.json').write_text(json.dumps(callers, ensure_ascii=False, indent=2) + '\n', encoding='utf-8')
print(text[:10000])
