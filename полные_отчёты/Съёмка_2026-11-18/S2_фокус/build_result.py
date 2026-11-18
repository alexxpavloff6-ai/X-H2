from __future__ import annotations

import csv
import json
import struct
import sys
from pathlib import Path

TASK = Path(__file__).resolve().parent
ROOT = TASK.parents[2]
AN = ROOT / "Анализ_прошивки"
K2 = AN / "Камера_2026-11-17" / "K2_прошивка"
FW = AN / "Сравнение_версий_2026-11-16"
BACKUP = AN / "Зерно_2026-11-18" / "опыт_камера" / "04_C7_D1A5_18_копия" / "backup.bin"
sys.path.insert(0, str(K2))
sys.path.insert(0, str(FW))
import decode_backup  # noqa: E402
from fwcommon import load  # noqa: E402


def hx(value: int | None) -> str | None:
    return None if value is None else f"0x{value:X}"


def transition(block, table: int, base: int, setting_id: int, floor: int) -> dict:
    entry = table + 2 * (setting_id - floor)
    rel = struct.unpack_from("<h", block.data, block.off(entry))[0]
    return {"table_entry": hx(entry), "relative_words": rel, "branch": hx(base + rel * 4)}


def main() -> None:
    bank = json.loads((K2 / "карта_банка.json").read_text(encoding="utf-8"))
    rows = bank["entries_mode1"]
    row_by_name = {row["name"]: row for row in rows}
    payload, meta, warnings = decode_backup.split_container(BACKUP.read_bytes())
    block = load("X-H2", "old", 1)

    groups = [
        {"topic": "режим фокуса", "usb": ["0x500A"], "usb_values": {"1": "MF", "0x8001": "AF-S", "0x8002": "AF-C"}, "setting_ids": [0x8C0], "note": "Подтверждено наблюдениями USB и таблицей 278 свойств."},
        {"topic": "режим и геометрия зоны AF", "usb": ["0x501C", "0xD02A", "0xD02B", "0xD02D", "0xD347", "0xD372", "0xD374", "0xD395"], "usb_values": {"0x501C": {"0x8001": "одна точка", "0x8002": "зона", "0x8003": "широкая область/слежение"}, "D347/D372/D374/D395": "строка x,y,тип; x от -12 до +12, y от -8 до +8; типы включают точку, широкую область и варианты зоны"}, "setting_ids": [0x6FB, 0x6FC, 0x6FD, 0x6FF, 0x700, 0x727], "note": "501C и три копии D02A/D02B/D02D имеют общий UI_SETP_FOCUS. Координатные строки отдельно не связаны с одним UI_SETP в таблице 278 свойств; UI_SETP_FOCUSPOINT и поля ориентации остаются кандидатами."},
        {"topic": "лица и глаза", "usb": ["0xD020", "0xD024"], "usb_values": {"D020": {"1": "вкл.", "2": "выкл."}, "D024": {"1": "выкл.", "2": "авто", "3": "приоритет правого глаза", "4": "вероятно левый, не подтверждено"}}, "setting_ids": [0x618, 0x61C], "note": "При распознавании объектов или MF камера сама отключала лица и глаза по наблюдениям USB."},
        {"topic": "распознавание объекта", "usb": ["0xD1BD"], "usb_values": {"1": "выкл.", "2": "животные", "3": "птицы", "4–7": "ещё четыре вида, точные подписи не установлены"}, "setting_ids": [0x618, 0x620, 0x622, 0x624, 0x625], "note": "Ветка D1BD/UI_SETP_DETECT_SUBJECT_QMENU (0x622) переводит выбор в UI_SETP_DETECT_SUBJECT (0x620), обновляет статусные поля 0x624/0x625 и при значениях, отличных от 6, принудительно выключает UI_SETP_FACEDETECT (0x618)."},
        {"topic": "набор AF-C и три параметра", "usb": ["0xD232", "0xD233"], "usb_values": {"D232": "набор 1–6", "D233": "тройка значений: слежение 0–4, реакция на смену скорости 0–2, выбор зоны 0–2"}, "setting_ids": [0x70D, 0x710, 0x711, 0x712, 0x713, 0x714, 0x715, 0x717, 0x718, 0x719, 0x71A, 0x71B, 0x71C, 0x71E, 0x71F, 0x720, 0x721, 0x722, 0x723], "note": "Связка D233 → TARGET_CHASE1–6 / TARGET_SPEED1–6 / TARGET_PRIORITY1–6 выведена по внутренним именам и порядку полей; MOVIE-поля отдельны."},
        {"topic": "PRE-AF", "usb": ["0xD34B"], "usb_values": {"1": "вкл. по умолчанию", "другие": "список допустимых кодов USB в снимках не проверен"}, "setting_ids": [0x1E2], "note": "Соседнее кино-поле 0x1E3."},
        {"topic": "приоритет спуска/фокуса", "usb": [], "usb_values": None, "setting_ids": [], "note": "В USB-таблице 278 свойств отдельного свойства приоритета AF-S/AF-C нет. Символы MODE_RELEASE_FOCUS_PRIORITY_RELEASE/FOCUS не являются UI_SETP-идентификаторами; сопоставление не установлено."},
        {"topic": "Boost / производительность", "usb": ["0xD304"], "usb_values": {"1": "Normal", "2": "Economy", "3": "Boost со слабым освещением", "4": "Boost + разрешение", "5": "Boost 120P", "7": "Boost 240P"}, "setting_ids": [0x5BA, 0x5BB, 0x5BC, 0x5BD, 0x5BE], "note": "Таблица свойства называет 0x5BE UI_SETP_FUNC_PERFORMANCE; ветка использует соседние PERFORMANCE/PERFORMANCE_MODE поля. USB-значения не тождественны внутреннему словарю performance."},
    ]

    all_ids = sorted({i for group in groups for i in group["setting_ids"]})
    settings = []
    known_names = {0x5BE: "UI_SETP_FUNC_PERFORMANCE", 0x622: "UI_SETP_DETECT_SUBJECT_QMENU"}
    for setting_id in all_ids:
        candidate_names = [name for name, row in row_by_name.items() if (int(row["id"], 0) if isinstance(row["id"], str) else row["id"]) == setting_id and str(row["layout_mode"]) == "1" and str(row["selector_mode"]) == "1"]
        rows_for_id = [row_by_name[name] for name in candidate_names]
        bank_fields = []
        for row in rows_for_id:
            if row["segment"] != "custom_0x1C00" or not row["blob_offset"]:
                continue
            off = int(row["blob_offset"], 0) if isinstance(row["blob_offset"], str) else row["blob_offset"]
            size = int(row["size"])
            values = []
            for slot in range(7):
                start = off + slot * 0x400
                if start + size <= len(payload):
                    values.append(int.from_bytes(payload[start:start+size], "little", signed=row["type"] == "s16"))
                else:
                    values.append(None)
            file_off = row["container_offset"]
            if isinstance(file_off, str) and file_off:
                file_off = int(file_off, 0)
            bank_fields.append({"name": row["name"], "segment": row["segment"], "C1_payload_offset": hx(off), "file_offset": hx(file_off) if file_off else None, "type": row["type"], "size": size, "C1_to_C7_values": values})
        settings.append({
            "id": hx(setting_id),
            "name": rows_for_id[0]["name"] if rows_for_id else known_names.get(setting_id),
            "setter": transition(block, 0x33A77E8, 0x2C88F50, setting_id, 0xB),
            "getter": transition(block, 0x33A929C, 0x2C9403C, setting_id, 0xF),
            "bank_fields_in_C1_C7_backup": bank_fields,
        })

    result = {
        "title": "Карта фокуса X-H2 5.30",
        "sources": {"firmware_block": str(FW / "blocks" / "X-H2_5.30_b1_0x840274.bin"), "bank_map": str(K2 / "карта_банка.json"), "backup": str(BACKUP), "backup_payload_offset": hx(meta["payload_offset"]), "backup_warnings": warnings, "usb_reference": "Автофокус_по_USB.md и Таблица_278_свойств_из_прошивки.tsv; снимки USB от 10.11.2026"},
        "dispatch": {"setter_function": "0x2C88E98", "setter_table": "0x33A77E8", "setter_index": "id - 0xB", "getter_function": "0x2C93FD4", "getter_table": "0x33A929C", "getter_index": "id - 0xF", "relative_base_getter": "0x2C9403C"},
        "topics": groups,
        "settings": settings,
        "reader_candidates_outside_general_getter": [
            {"setting_ids": ["0x618"], "call_site": "0x2BD56D0", "also_at": ["0x2BD56E8", "0x2BD5700"], "evidence": "Непосредственно перед BL 0x2C93FD4 загружается id 0x618; далее результат используется при записи соседних 0xACC/0xACD и id 0x624.", "confidence": "Кандидат: потребитель и полный смысл полей не установлены."},
            {"setting_ids": ["0x618"], "call_site": "0x2BF948C", "evidence": "Отдельный прямой вызов общего геттера с id 0x618.", "confidence": "Кандидат на логику распознавания лиц."},
            {"setting_ids": ["0x61C"], "call_site": "0x2BFBB44", "evidence": "Отдельный прямой вызов общего геттера с id 0x61C.", "confidence": "Кандидат на логику выбора глаза."},
            {"setting_ids": ["0x5BE"], "call_site": "0x2BFEEBC", "evidence": "Отдельный прямой вызов общего геттера с id 0x5BE.", "confidence": "Кандидат на потребление режима производительности."},
            {"setting_ids": ["0x622"], "call_site": "0x2BFEFCC", "evidence": "Отдельный прямой вызов общего геттера с id 0x622.", "confidence": "Кандидат на распознавание объекта."},
            {"setting_ids": ["0x715", "0x71C", "0x723"], "call_sites": ["0x2BF87A8", "0x2BF87D8", "0x2BF8808"], "evidence": "Соседние вызовы читают по одному полю чувствительности каждого из трёх наборов 5/6.", "confidence": "Кандидат на сборку параметров AF-C; функция выше по стеку не идентифицирована."},
        ],
        "dependencies": ["USB-наблюдение: распознавание объектов или MF сопровождается автоматическим отключением лиц/глаз.", "USB-наблюдение: позиция объектива D171 выдаётся только в MF.", "Сеттер D232 сохраняет выбранный набор и вызывает несколько обслуживающих функций; изменение D233 относится к трём параметрам выбранного набора.", "Для AF-S/AF-C приоритетов, точных вызовов подсистемы AF и связи с фазовыми данными данных пока нет."],
        "limits": ["Числа банка ниже относятся к сохранённым профилям C1–C7; их нельзя автоматически считать текущими live-настройками.", "Статическая адресация общего сеттера/геттера подтверждена по таблицам переходов. Ветви D233 и координатных строк не сведены полностью к конкретным меню-состояниям.", "Поля вне сегментов экспортируемого резервного снимка и отдельные состояния не трактуются как отсутствующие в устройстве."],
    }
    (TASK / "результат.json").write_text(json.dumps(result, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")
    print(json.dumps({"output": str(TASK / "результат.json"), "settings": len(settings), "backup_bytes": len(payload), "bank_fields": sum(len(s["bank_fields_in_C1_C7_backup"]) for s in settings)}, ensure_ascii=False))


if __name__ == "__main__":
    main()
