"""Сохраняет таблицы преобразования, относящиеся к R1, из блока 0."""
from __future__ import annotations

import json
import struct
import sys
from pathlib import Path

TASK = Path(__file__).resolve().parent
ROOT = TASK.parents[2]
ANALYSIS = ROOT / "\u0410\u043d\u0430\u043b\u0438\u0437_\u043f\u0440\u043e\u0448\u0438\u0432\u043a\u0438"
sys.path.insert(0, str(ANALYSIS / "\u0421\u0440\u0430\u0432\u043d\u0435\u043d\u0438\u0435_\u0432\u0435\u0440\u0441\u0438\u0439_2026-11-16"))
from fwcommon import load  # noqa: E402

CONVERTERS = {
    0x670: "UI_SETP_QUALITY",
    0x68E: "UI_SETP_FILM_SIM",
    0x6A2: "UI_SETP_BLACK_TONE",
    0x6A4: "UI_SETP_BLACK_TONE_RG",
    0x6A6: "UI_SETP_DRANGE",
    0x6B0: "UI_SETP_WIDEDRANGE",
}
SENTINEL = 0x7FFFFFFE


def main() -> None:
    block = load("X-H2", "old", 0)
    output = {
        "firmware": "X-H2 5.30",
        "block": "b0, base 0x1101000",
        "converter_table_base": "0x1BD5AB8",
        "record_size": 16,
        "sentinel_value": "0x7FFFFFFE",
        "property_tables": {},
    }
    for setting_id, name in CONVERTERS.items():
        pointer_offset = 0x1BD5AB8 + setting_id * 8 - block.base
        pointer = struct.unpack_from("<Q", block.data, pointer_offset)[0]
        table_offset = pointer - block.base
        rows = []
        for index in range(64):
            values = struct.unpack_from("<4I", block.data, table_offset + index * 16)
            if all(value == 0xFFFFFFFF for value in values):
                break
            rows.append({"row": index, "columns_u32": [f"0x{value:08X}" for value in values]})
        output["property_tables"][f"0x{setting_id:X}"] = {
            "name": name,
            "pointer_entry": f"0x{0x1BD5AB8 + setting_id * 8:X}",
            "table_address": f"0x{pointer:X}",
            "rows": rows,
            "candidate_usb_to_bank_col0_col3": [
                {"usb": row["columns_u32"][3], "bank": row["columns_u32"][0], "row": row["row"]}
                for row in rows
                if row["columns_u32"][0] != "0x7FFFFFFE"
                and row["columns_u32"][3] != "0x7FFFFFFE"
                and row["columns_u32"][3] != "0xFFFFFFFF"
            ],
        }

    size_address = 0x18BBCF0
    size_offset = size_address - block.base
    output["image_size_table"] = {
        "address": f"0x{size_address:X}",
        "record_size": 28,
        "rows": [
            [f"0x{value:X}" for value in struct.unpack_from("<7I", block.data, size_offset + i * 28)]
            for i in range(26)
        ],
    }
    target = TASK / "\u0442\u0430\u0431\u043b\u0438\u0446\u044b_\u043f\u0440\u0435\u043e\u0431\u0440\u0430\u0437\u043e\u0432\u0430\u043d\u0438\u044f.json"
    target.write_text(json.dumps(output, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")
    print(f"Saved {target}")


if __name__ == "__main__":
    main()
