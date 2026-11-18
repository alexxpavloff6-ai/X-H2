"""Повторно извлекает байты полей слотов из резервной копии X-H2 5.30."""
from __future__ import annotations

import importlib.util
import json
import re
from pathlib import Path

TASK = Path(__file__).resolve().parent
ROOT = TASK.parents[2]
ANALYSIS = ROOT / "\u0410\u043d\u0430\u043b\u0438\u0437_\u043f\u0440\u043e\u0448\u0438\u0432\u043a\u0438"
CARD = ANALYSIS / "\u041a\u0430\u043c\u0435\u0440\u0430_2026-11-17" / "K2_\u043f\u0440\u043e\u0448\u0438\u0432\u043a\u0430"
BACKUP = (
    ANALYSIS / "\u0417\u0435\u0440\u043d\u043e_2026-11-18" / "\u043e\u043f\u044b\u0442_\u043a\u0430\u043c\u0435\u0440\u0430"
    / "04_C7_D1A5_18_\u043a\u043e\u043f\u0438\u044f" / "backup.bin"
)
MAP = CARD / "\u043a\u0430\u0440\u0442\u0430_\u0431\u0430\u043d\u043a\u0430.json"
PTP = ANALYSIS / "PTP_\u0447\u0442\u0435\u043d\u0438\u0435_2026-11-10" / "xh2_slots_C1-C7_072426.txt"
FIELDS = {
    0x66A: "UI_SETP_PIXEL",
    0x66F: "UI_SETP_ASPECT",
    0x670: "UI_SETP_QUALITY",
    0x6A6: "UI_SETP_DRANGE",
    0x6B0: "UI_SETP_WIDEDRANGE",
    0x68E: "UI_SETP_FILM_SIM",
    0x6A2: "UI_SETP_BLACK_TONE",
    0x6A4: "UI_SETP_BLACK_TONE_RG",
}


def load_decoder():
    spec = importlib.util.spec_from_file_location("xh2_readonly_backup_decoder", CARD / "decode_backup.py")
    assert spec and spec.loader
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def main() -> None:
    mapping = json.loads(MAP.read_text(encoding="utf-8"))
    entries = mapping["entries_mode1"]
    raw = BACKUP.read_bytes()
    payload, container, warnings = load_decoder().split_container(raw)
    result = {
        "source_backup": str(BACKUP),
        "payload_offset_in_file": container["payload_offset"],
        "slot_stride": "0x400",
        "fields": {},
        "warnings": warnings,
    }
    ptp_text = PTP.read_text(encoding="utf-8")
    name_line = re.search(r"C1 0xD18D resp 0x2001 data ([0-9a-fA-F]+)", ptp_text)
    if name_line:
        name_data = bytes.fromhex(name_line.group(1))
        c1_name = name_data[1:].decode("utf-16le", errors="ignore").rstrip("\x00")
        name_bytes = c1_name.encode("utf-16le")
        result["D18D_C1_name_search"] = {
            "name": c1_name,
            "found_in_backup_file": raw.find(name_bytes) >= 0,
            "note": "Поиск проверяет только буквальную строку UTF-16LE в образе; отрицательный результат не исключает отдельное хранилище или кодирование.",
        }
    for setting_id, name in FIELDS.items():
        row = next(r for r in entries if r["id"] == setting_id and r["custom_slot"] == 0)
        start = int(row["blob_offset"], 0)
        result["fields"][f"0x{setting_id:X}"] = {
            "name": name,
            "C1_blob_offset": f"0x{start:X}",
            "type": row["type"],
            "values_C1_C7": [payload[start + 0x400 * i] for i in range(7)],
        }
    (TASK / "извлечённые_байты.json").write_text(
        json.dumps(result, ensure_ascii=False, indent=2) + "\n", encoding="utf-8"
    )
    print(json.dumps(result, ensure_ascii=True, indent=2))


if __name__ == "__main__":
    main()
