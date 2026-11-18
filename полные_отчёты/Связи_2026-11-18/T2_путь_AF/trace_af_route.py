import json
import sys
from pathlib import Path
sys.path.insert(0, r'<корень проекта>\Анализ_прошивки\Сравнение_версий_2026-11-16')
from fwcommon import load, adrp_refs, bl_callers, func_start, dis

ROOT = Path(__file__).resolve().parent
b0 = load('X-H2', 'old', 0)
b1 = load('X-H2', 'old', 1)
b2 = load('X-H2', 'old', 2)

# Функции AF по предыдущему поиску прямых вызовов общего геттера и трассировке сеттера.
xrefs = json.loads((ROOT / 'xref_check.json').read_text(encoding='utf-8'))
af_functions = {int(row['function'], 16) for row in xrefs['calls']}
af_functions.update({
    0x12F0BD4, 0x12F0C6C, 0x12F0D04,
    0x1326F70, 0x1326F9C, 0x1326FC8,
    0x1338C70, 0x1338C9C, 0x1338CC8,
})

def table_values(block, address, count):
    return [block.u32(address + 4 * index) for index in range(count)]

def api_rows(target):
    rows = []
    for index, block in enumerate((b0, b1, b2)):
        sites = bl_callers(block, target)
        functions = {func_start(block, site) for site, _kind in sites}
        rows.append({
            'block': index,
            'direct_call_sites': len(sites),
            'af_related_function_overlap': [hex(fn) for fn in sorted(functions & af_functions) if fn],
        })
    return rows

result = {
    'tables': {
        '0x3456B20': {
            'shape': [41, 6],
            'values': sorted(set(table_values(b1, 0x3456B20, 41 * 6))),
            'references': adrp_refs(b1, 0x3456B20),
            'lookup': dis(b1, 0x2F85F3C, 13),
        },
        '0x3456EF8': {
            'shape': [41],
            'values': sorted(set(table_values(b1, 0x3456EF8, 41))),
            'references': adrp_refs(b1, 0x3456EF8),
            'lookup': dis(b1, 0x2F85F70, 7),
        },
    },
    'record_api_intersections': {
        '0x14CF124_set': api_rows(0x14CF124),
        '0x14CF354_get': api_rows(0x14CF354),
        '0x14C6384_direct_callers': [
            {'block': index, 'sites': [hex(site) for site, _kind in bl_callers(block, 0x14C6384)]}
            for index, block in enumerate((b0, b1, b2))
        ],
        'verified_call_sites': {
            '0x311B788': dis(b1, 0x311B768, 9),
            '0x31053F8': dis(b1, 0x31053F0, 5),
            '0x14C6384': dis(b0, 0x14C6384, 2),
            '0x14C648C': dis(b0, 0x14C6488, 6),
            '0x14CF4C8': dis(b0, 0x14CF4C4, 3),
        },
    },
    'afc_handlers': {
        hex(address): {
            'disassembly': dis(b0, address, 40),
            'direct_global_refs': {
                hex(global_address): adrp_refs(b0, global_address, window=20)
                for global_address in (0x2680474, 0x2680478, 0x268047C)
            },
        }
        for address in (0x12F0BD4, 0x12F0C6C, 0x12F0D04)
    },
}
print(json.dumps(result, ensure_ascii=False, indent=2))
