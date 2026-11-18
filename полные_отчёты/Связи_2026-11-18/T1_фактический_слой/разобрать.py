"""Печатает подтверждающий код для T1 X-H2 5.30 и эмулирует чистую функцию нормализации."""
from contextlib import redirect_stdout
from io import StringIO
from pathlib import Path
import sys

ROOT = Path(r"<корень проекта>/Анализ_прошивки/Сравнение_версий_2026-11-16")
sys.path.insert(0, str(ROOT))
from fwcommon import load, dis


def main():
    b0 = load("X-H2", "old", 0)
    b1 = load("X-H2", "old", 1)
    sections = [
        (b1, 0x2DB225C, 12, "Событие и происхождение w23"),
        (b1, 0x2DB2660, 24, "Условия и запись фактического типа"),
        (b1, 0x2DA3838, 9, "Первый источник нормализуемого значения"),
        (b1, 0x2DA39CC, 24, "Альтернативные источники значения"),
        (b1, 0x2DA3F40, 10, "Запись из вычисленного w22"),
        (b1, 0x2DB3AB8, 20, "Инициализация указателей контекста"),
        (b1, 0x2DB3C90, 8, "Копирование из поля +0x178"),
        (b1, 0x2DBBDAC, 9, "Копирующий обработчик"),
        (b1, 0x2DB737C, 24, "Копирование из снимка состояния"),
        (b1, 0x2E8C624, 20, "Условная общая запись"),
        (b0, 0x14F5104, 8, "Нормализатор перечисления"),
        (b0, 0x14E6D8C, 8, "Чтение и запись кэша выдержки"),
        (b0, 0x14E75C0, 150, "Вычислитель фактической выдержки"),
        (b0, 0x14EFDC4, 52, "Переход к преобразованию выдержки"),
        (b0, 0x14EFC40, 48, "Вспомогательное преобразование выдержки"),
        (b1, 0x2DB2B50, 42, "Пересчёт и обновление кэша выдержки"),
    ]
    for block, address, count, title in sections:
        print(f"\n## {title} ({address:#x})")
        print(dis(block, address, count))

    print("\n## Указатель глобального контекста")
    owner_base = 0x3BC2000 + 0xB48 + 0x8000
    pointer_slot = owner_base + 0x3478
    print(f"base={owner_base:#x}; pointer_slot={pointer_slot:#x}")

    print("\n## Unicorn: изолированная функция 0x14F5104")
    try:
        from unicorn import Uc, UC_ARCH_ARM64, UC_MODE_ARM
        from unicorn.arm64_const import UC_ARM64_REG_X0, UC_ARM64_REG_X30
    except ImportError as exc:
        print(f"Unicorn недоступен: {exc}")
        return
    start, ret_addr = 0x14F5104, 0x14F5FF0
    code = b0.data[b0.off(start):b0.off(start) + 0x20]

    def emulate(value):
        uc = Uc(UC_ARCH_ARM64, UC_MODE_ARM)
        uc.mem_map(0x14F5000, 0x2000)
        uc.mem_write(start, code)
        uc.reg_write(UC_ARM64_REG_X0, value)
        uc.reg_write(UC_ARM64_REG_X30, ret_addr)
        uc.emu_start(start, ret_addr, count=20)
        return uc.reg_read(UC_ARM64_REG_X0)

    for value in (0, 1, 2, 3, 4, 0xFFFF):
        print(f"enum={value:#x} -> {emulate(value):#x}")
    for speed in ("1/2000", "1/8000", "1/16000"):
        print(f"MS+ES при {speed}: enum 2 -> {emulate(2)} (выдержка в функцию не передаётся)")


buffer = StringIO()
with redirect_stdout(buffer):
    main()
output = buffer.getvalue()
Path(__file__).with_name("код_выдержек.txt").write_text(output, encoding="utf-8")
print("Сохранены фрагменты кода и результат Unicorn в код_выдержек.txt")
