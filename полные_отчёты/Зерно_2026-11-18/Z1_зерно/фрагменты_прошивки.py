import sys

sys.path.insert(0, r'<корень проекта>\Анализ_прошивки\Сравнение_версий_2026-11-16')
from fwcommon import load, dis

b0 = load('X-H2', 'old', 0)  # X-H2 5.30, block 0, base 0x1101000
b1 = load('X-H2', 'old', 1)  # X-H2 5.30, block 1, base 0x29AE000
print('--- UI_SETP bank getter and grain cases ---')
print(dis(b0, 0x12AA788, 17))
print(dis(b0, 0x12B71C4, 24))
print(dis(b0, 0x12B727C, 24))
print('--- Slot-property group builder ---')
print(dis(b1, 0x2F2CDE0, 24))
print('--- Registry entry words ---')
for va in range(0x3443590, 0x34435E0, 4):
    print(f'{va:#x}: {b1.u32(va):#06x}')
