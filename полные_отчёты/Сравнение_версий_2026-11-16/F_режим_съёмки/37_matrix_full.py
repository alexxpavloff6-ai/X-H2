"""F: полная матрица функции B (0x2b47bb8): (mode, sub, p) -> сайт отправки 0x358.

Сохранение: matrix_358.json. busy=0 (свободно), flag10=1, aux(0x2a02384)=0x55.
Пути: 'direct'  = 0x2b47cd8 (без предкоманды, сразу 0x130cd44),
      'pre_19F' = 0x2b47dc8 (перед 0x358 вызывается 0x19F через 0x2c151d8),
      'pre_1A0' = 0x2b47da8 (busy!=0: 0x1A0 через 0x2c15200).
"""
import sys, json, importlib.util
sys.path.insert(0, '<корень проекта>/Анализ_прошивки/Сравнение_версий_2026-11-16/F_режим_съёмки')
spec = importlib.util.spec_from_file_location('vm33', '<корень проекта>/Анализ_прошивки/Сравнение_версий_2026-11-16/F_режим_съёмки/33_vm_sites.py')
vm = importlib.util.module_from_spec(spec)
spec.loader.exec_module(vm)
run = vm.run

SITE = {0x2b47cdc: 'direct', 0x2b47dcc: 'pre_19F', 0x2b47dac: 'pre_1A0', 0x2b47bac: 'A_pre_19F'}

out = {}
for mode in (0x14, 0x8, 0xd, 0xc, 0x4, 0x15):
    for sub in range(0, 0x11):
        for p in (0, 1, 2, 3):
            r = run(0x2b47bb8, mode, sub, p, 1, 0, 0x55)
            path = [SITE.get(a, hex(a)) for a, c in r if c == 0x358]
            out[f'{mode:#x}|{sub:#x}|{p}'] = path
json.dump(out, open('matrix_358.json', 'w'), indent=1)

# сводка по sub/p для mode=0x14
print('mode=0x14: sub x p -> путь')
print('sub  p0        p1        p2        p3')
for sub in range(0, 0x11):
    row = []
    for p in (0, 1, 2, 3):
        row.append(','.join(out[f'{0x14:#x}|{sub:#x}|{p}']) or '-')
    print(f'{sub:#04x} ' + '  '.join(f'{c:8s}' for c in row))
for mode in (0x8, 0xd, 0xc, 0x4, 0x15):
    print(f'mode={mode:#x}: ' + ', '.join(sorted({','.join(out[f"{mode:#x}|{s:#x}|{p}"]) or '-' for s in range(4) for p in range(4)})))
