"""F: матрица для функции B — какой сайт отправляет 0x358 при (mode, sub, p)."""
import sys, importlib.util
sys.path.insert(0, '<корень проекта>/Анализ_прошивки/Сравнение_версий_2026-11-16/F_режим_съёмки')

spec = importlib.util.spec_from_file_location('vm33', '<корень проекта>/Анализ_прошивки/Сравнение_версий_2026-11-16/F_режим_съёмки/33_vm_sites.py')
vm = importlib.util.module_from_spec(spec)
spec.loader.exec_module(vm)
run = vm.run

print('mode  sub  p  -> 0x358 sites | все отправленные коды')
for mode in (0x14, 0x8, 0xd, 0x12, 0x15, 1, 3):
    for sub in (0, 1, 2, 3, 0xb, 0xc, 0xd, 0xe):
        for p in (0, 1, 2, 3):
            s = run(0x2b47bb8, mode, sub, p, 1, 1, 0x55)
            sites = sorted({hex(a) for a, c in s if c == 0x358})
            print(f'{mode:#04x} {sub:#04x} {p} -> {sites} | {[hex(c) for a, c in s]}')
