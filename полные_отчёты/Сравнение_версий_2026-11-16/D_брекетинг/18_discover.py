# -*- coding: utf-8 -*-
"""D: быстрая разведка адресов для VM/отчёта (word-префильтр, без полного disasm).

Якоря:
 - группа свойства 0x916f: `mov w0,#0x916f; movk w0,#1,lsl#16`;
 - вставка `mov w0,#0x9155; movk w0,#1,lsl#16` (только new);
 - вход функции подготовки кадра: `stp x29,x30,[sp,#-0x70]!` + `mov x29,sp`;
 - property_getter(u16) = цель bl сразу после вставки (блок 0);
 - глобал-указатель blob — в теле геттера;
 - копировщик commit->per-frame: `mov w0,#0xa8; bl; tbnz w0,#7`.
"""
import sys, re, struct, json
sys.path.insert(0, r'<корень проекта>\Анализ_прошивки\Сравнение_версий_2026-11-16\D_брекетинг')
from dhelp import *  # noqa

def movz(reg, imm, hw=0):
    return 0x52800000 | (hw << 21) | (imm << 5) | reg

def movk(reg, imm, hw=0):
    return 0x72800000 | (hw << 21) | (imm << 5) | reg

GROUP = struct.pack('<II', movz(0, 0x916f), movk(0, 1, 1))
PATCH = struct.pack('<II', movz(0, 0x9155), movk(0, 1, 1))
MOV_A8 = movz(0, 0xa8)

def find_copiers(b):
    out = []
    d = b.data
    for o in range(0, len(d) - 12, 4):
        if struct.unpack_from('<I', d, o)[0] != MOV_A8:
            continue
        w1, w2 = struct.unpack_from('<II', d, o + 4)
        if (w1 & 0xfc000000) != 0x94000000:
            continue
        if (w2 & 0xfff8001f) != 0x37000000:
            continue
        out.append(b.base + o)
    return out

INFO = {}
for m in MODELS:
    for st in ('old', 'new'):
        b1 = load(m, st, 1)
        g = find_bytes(b1, GROUP)
        p = find_bytes(b1, PATCH)
        rec = {'group_916f': g[0] if g else None, 'patch': p[0] if p else None}
        anchor = rec['patch'] or rec['group_916f']
        start = None
        for k in range(anchor & ~3, anchor - 0x3000, -4):
            w = struct.unpack_from('<I', b1.data, b1.off(k))[0]
            if w == 0xa9ba7bfd:
                nxt = insns(b1, k + 4, 2)
                if nxt and nxt[0].mnemonic == 'mov' and nxt[0].op_str == 'x29, sp':
                    start = k
                    break
        rec['func_start'] = start
        if rec['patch']:
            bl = insns(b1, rec['patch'] + 8, 1)[0]
            tgt = int(bl.op_str.split('#')[1], 0)
            b0 = load(m, st, 0)
            gs = insns(b0, tgt, 8)
            page, glob = None, None
            for x in gs:
                if x.mnemonic == 'adrp':
                    page = int(x.op_str.split('#')[1], 0)
                m2 = re.search(r'\[x\d+, #0x([0-9a-f]+)\]', x.op_str)
                if x.mnemonic == 'ldr' and m2 and page:
                    glob = page + int(m2.group(1), 16)
            rec['getter'] = tgt
            rec['blob_global'] = glob
        rec['copiers'] = find_copiers(b1)
        INFO[f'{m} {st}'] = rec
        print(m, st, {k: ([hex(q) for q in v] if isinstance(v, list)
                          else (hex(v) if isinstance(v, int) else v))
                      for k, v in rec.items()})

json.dump({k: {kk: ([hex(q) for q in vv] if isinstance(vv, list)
                   else (hex(vv) if isinstance(vv, int) else vv))
               for kk, vv in v.items()} for k, v in INFO.items()},
          open('discover.json', 'w', encoding='utf8'), ensure_ascii=False, indent=1)
print('\nсохранено в discover.json')
