"""Только читающая сверка ключевых адресов USB-события X-H2 5.30."""
from pathlib import Path
import json
import sys

sys.dont_write_bytecode = True
ROOT = Path(__file__).resolve().parents[3]
FW_DIR = next(p for p in (ROOT / "Анализ_прошивки").glob("Сравнение_версий_2026-11-16") if p.is_dir())
sys.path.insert(0, str(FW_DIR))
from fwcommon import load, bl_callers, dis, adrp_refs, find_bytes  # noqa: E402


def main():
    b0 = load("X-H2", "old", 0)
    b1 = load("X-H2", "old", 1)
    targets = [0x2BDFBCC, 0x2C88E98, 0x2BBCB18, 0x12E863C]
    callers = {
        hex(target): [
            {"адрес": hex(site), "тип": kind}
            for site, kind in bl_callers(b1, target)
        ]
        for target in targets
    }
    event_calls = [site for site, kind in bl_callers(b1, 0x12E863C) if kind == "bl"]
    event_1f_calls = []
    for site in event_calls:
        window = dis(b1, site - 0x30, 13)
        if "mov w0, #0x1f" in window.lower() or "mov w0, #31" in window.lower():
            event_1f_calls.append({"адрес": hex(site), "контекст": window})
    errors = {}
    for code in (0x201C, 0x2001):
        errors[hex(code)] = {
            "блок_0": [hex(a) for a in find_bytes(b0, code.to_bytes(2, "little"))[:40]],
            "блок_1": [hex(a) for a in find_bytes(b1, code.to_bytes(2, "little"))[:40]],
        }
    result = {
        "вызовы_из_блока_1": callers,
        "шина_событий_12e863c": {
            "прямых_вызовов_в_блоке_1": len(event_calls),
            "вызовов_с_непосредственным_событием_0x1f": event_1f_calls,
            "вызовы_в_диапазонах": {
                "0x2A40000-0x2A60000": sum(0x2A40000 <= a < 0x2A60000 for a in event_calls),
                "0x2BD0000-0x2C00000": sum(0x2BD0000 <= a < 0x2C00000 for a in event_calls),
            },
        },
        "ссылки_на_поля_контекста_в_блоке_1": {
            hex(address): adrp_refs(b1, address, 16)
            for address in (0x26B7998, 0x26B799C, 0x26C0DF4, 0x26C0E60)
        },
        "совпадения_кодов_статуса": errors,
        "дизассемблирование": {
            "0x2BDFBCC": dis(b1, 0x2BDFBCC, 36),
            "0x2A4BD04": dis(b1, 0x2A4BD04, 31),
            "0x2BA9B14": dis(b1, 0x2BA9AF4, 9),
            "0x2A3D2EC": dis(b1, 0x2A3D2EC, 8),
            "0x2A4A678": dis(b1, 0x2A4A678, 12),
            "0x2A49BC0": dis(b1, 0x2A49BC0, 12),
            "0x2A4E9D0": dis(b1, 0x2A4E9D0, 12),
            "0x12E863C": dis(b0, 0x12E863C, 31),
        },
        "проверка_вычисления_адреса": {
            "adrp": "0x26A7000",
            "add_a8": "0xA8",
            "add_shifted": "0x10 << 12 = 0x10000",
            "base": "0x26B70A8",
            "id": "base + 0x8F0 = 0x26B7998",
            "value": "base + 0x8F4 = 0x26B799C",
            "отдельная_копия": "назначение 0x26B7994, источник 0x26B7980, 0x14 байт; ветвь 0x1F читает id/value по 0x26B7998/0x26B799C"
        },
        "проверка_адресов_ptp": {
            "база": "0x26A7000 + 0xA8 + 0x18000 = 0x26BF0A8",
            "код_свойства": "база + 0x1D4C = 0x26C0DF4",
            "поле_проверки_в_0x2a4bd04": "база + 0x1DB8 = 0x26C0E60"
        },
        "примечание": "Скрипт читает извлечённые блоки прошивки через fwcommon.py и печатает сводку в stdout; файлы проекта не меняет.",
    }
    print(json.dumps(result, ensure_ascii=False, indent=2))


if __name__ == "__main__":
    main()

