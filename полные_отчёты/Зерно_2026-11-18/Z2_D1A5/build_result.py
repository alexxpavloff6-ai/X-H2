"""Собирает офлайн-сверку свойств D18C–D1A5 из локальных материалов X-H2."""
from __future__ import annotations

import csv
import importlib.util
import json
import struct
from pathlib import Path

ROOT = Path(r"<корень проекта>")
AN = ROOT / "Анализ_прошивки"
OUT = AN / "Зерно_2026-11-18" / "Z2_D1A5"
CARD_DIR = AN / "Камера_2026-11-17" / "K2_прошивка"
SNAP_DIR = AN / "fujicli_2026-11-18" / "совместимость"
C2 = AN / "fujicli_2026-11-18" / "C2_модель_камеры" / "сопоставление.json"

# Имена получены по смыслу полей fujicli и сверены с индексами UI_SETP в карте BACKUP.
# Несколько USB-свойств являются составными или выбирают поле из семейства UI_SETP.
INTERNAL = {
    0xD18C: [(0x0DC, "UI_SETP_CUSTOM_SET_SAVE", "Д" )],
    0xD18D: [(0x730, "UI_SETP_CUSTOM_SAVE_NAME", "Д")],
    0xD18E: [(0x66A, "UI_SETP_PIXEL", "К"), (0x66F, "UI_SETP_ASPECT", "К")],
    0xD18F: [(0x670, "UI_SETP_QUALITY", "К")],
    0xD190: [(0x6A6, "UI_SETP_DRANGE", "К")],
    0xD191: [(0x6B0, "UI_SETP_WIDEDRANGE", "К")],
    0xD192: [(0x68E, "UI_SETP_FILM_SIM", "К")],
    0xD193: [(0x6A2, "UI_SETP_BLACK_TONE", "К")],
    0xD194: [(0x6A4, "UI_SETP_BLACK_TONE_RG", "К")],
    0xD195: [(0x106, "UI_SETP_GRAIN", "Д"), (0x107, "UI_SETP_GRAIN_SIZE", "Д")],
    0xD196: [(0x109, "UI_SETP_SHADOWING", "К")],
    0xD197: [(0x10A, "UI_SETP_BLUE_EFFECT", "К")],
    0xD198: [(0x10B, "UI_SETP_SMOOTH_SKIN", "К")],
    0xD199: [(0x5F5, "UI_SETP_WB", "К")],
    0xD19A: [(0x6BF, "UI_SETP_WB_TUNING_R", "К")],
    0xD19B: [(0x6DD, "UI_SETP_WB_TUNING_B", "К")],
    0xD19C: [(0x5F7, "UI_SETP_WB_KELVIN", "К")],
    0xD19D: [(0x6B9, "UI_SETP_HIGHLIGHT", "К")],
    0xD19E: [(0x6BB, "UI_SETP_SHADOW", "К")],
    0xD19F: [(0x6B3, "UI_SETP_STILLCOLOR", "К")],
    0xD1A0: [(0x6B5, "UI_SETP_SHARPNESS", "К")],
    0xD1A1: [(0x603, "UI_SETP_NR", "К")],
    0xD1A2: [(0x605, "UI_SETP_CLARITY", "К")],
    0xD1A3: [(0x615, "UI_SETP_LEQ", "К")],
    0xD1A4: [(0x104, "UI_SETP_COLOR_SPACE", "К")],
}
SIGNED = {0xD193, 0xD194, 0xD19A, 0xD19B, 0xD19D, 0xD19E, 0xD19F, 0xD1A0, 0xD1A2}
PTP_DESC_278 = {
    0xD18C: {"type": "UINT16", "access": "чтение и запись", "form": "список", "default": "0x0001"},
    0xD18D: {"type": "STR", "access": "чтение и запись", "form": "нет", "default": "0x0000"},
}
WRITE_TESTED = {
    0xD18C, 0xD18D, 0xD18F, 0xD190, 0xD191, 0xD192, 0xD195,
    0xD196, 0xD197, 0xD199, 0xD19A, 0xD19B, 0xD19D, 0xD19E,
    0xD19F, 0xD1A0, 0xD1A1, 0xD1A2, 0xD1A3, 0xD1A4,
}


def load_json(p: Path):
    return json.loads(p.read_text(encoding="utf-8"))


def load_backup_decoder():
    p = CARD_DIR / "decode_backup.py"
    spec = importlib.util.spec_from_file_location("xh2_backup_decoder_readonly", p)
    mod = importlib.util.module_from_spec(spec)
    assert spec and spec.loader
    spec.loader.exec_module(mod)
    return mod


def format_domain(opt: dict | None) -> tuple[str, str]:
    if not opt:
        return "не описано", "не установлено"
    if opt.get("kind") == "string":
        return "строка", "строка длиной до 25 символов (fujicli)"
    variants = opt.get("variants") or []
    if variants:
        labels = []
        for v in variants:
            wire = v.get("wire_value", "?")
            labels.append(f"{wire}={v['name']}")
        extra = ""
        if opt.get("id") == "grain_effect":
            extra = "; fujicli также читает 0x06 и 0x07 как Off"
        return "список", "; ".join(labels) + extra
    if opt.get("min") is not None:
        lo, hi, step = opt["min"], opt["max"], opt.get("step")
        scale = opt.get("scale")
        note = f"; масштаб USB/внутреннего значения ×{scale}" if scale and scale != 1 else ""
        st = f", шаг {step}" if step is not None else ""
        return "диапазон", f"{lo}…{hi}{st}{note}"
    return "не описано", "не установлено"


def main() -> None:
    OUT.mkdir(parents=True, exist_ok=True)
    schema = load_json(C2)
    options = {int(o["prop_code"], 16): o for o in schema["options"] if o.get("prop_code")}
    snapshot = load_json(SNAP_DIR / "снимки" / "04_после_set_c7" / "snapshot.json")
    slots = load_json(SNAP_DIR / "слоты_по_fujicli.json")["slots"]
    device_rows = {int(x["code"], 16): x for x in snapshot["properties"]}

    properties = []
    for code in range(0xD18C, 0xD1A6):
        opt = options.get(code)
        name = opt.get("name") if opt else None
        ptp = PTP_DESC_278.get(code)
        data = device_rows.get(code, {}).get("value", {}).get("data_hex", "")
        observed_len = len(bytes.fromhex(data)) if data else None
        if ptp:
            typ = ptp["type"]
            access = ptp["access"]
            form = ptp["form"]
            default = ptp["default"]
        elif code == 0xD18D:
            typ, access, form, default = "STR", "чтение и запись (по таблице 278)", "нет", "0x0000"
        elif code == 0xD1A5:
            typ, access, form, default = "UINT16 по длине ответа", "чтение подтверждено; запись не проверена", "не установлено", None
        else:
            typ = "INT16" if code in SIGNED else "UINT16"
            access = "чтение подтверждено; запись проверена" if code in WRITE_TESTED else "чтение подтверждено; запись в этой задаче не проверена"
            form, default = format_domain(opt)
            default = None
        schema_form, domain = format_domain(opt)
        internal = [{"id": f"0x{i:03X}", "name": n, "confidence": conf} for i, n, conf in INTERNAL.get(code, [])]
        slot_values = {}
        for slot, mapping in slots.items():
            item = mapping.get(f"0x{code:04X}")
            if item:
                slot_values[slot] = item[1]
        if code == 0xD1A5:
            slot_values = {slot: 7 for slot in slots}
        p = {
            "code": f"0x{code:04X}", "name_fujicli": name,
            "internal_settings": internal, "ptp_type": typ, "access": access,
            "form": form if ptp or code == 0xD1A5 else schema_form,
            "domain_fujicli": domain, "default_from_descriptor": default,
            "observed_value_bytes_C7": observed_len, "observed_value_hex_C7": data or None,
            "observed_slots": slot_values,
            "descriptor_status": "GetDevicePropDesc 0x1014 → GeneralError (0x2002), без данных" if not ptp else "строка таблицы 278; камера GetDevicePropDesc не отдаёт",
            "mapping_level": "Д" if code in (0xD18C, 0xD18D, 0xD195) else ("не найдено" if code == 0xD1A5 else "К"),
        }
        if opt:
            p["fujicli_option_id"] = opt.get("id")
            p["wire_lookup"] = opt.get("lookup")
            p["scale"] = opt.get("scale")
            p["min"] = opt.get("min")
            p["max"] = opt.get("max")
            p["step"] = opt.get("step")
        properties.append(p)

    # Проверяем фактические значения полей банка, которые совпали с D1A5=7.
    decoder = load_backup_decoder()
    fmap = decoder.load_map(CARD_DIR / "карта_банка.json")
    blob_path = SNAP_DIR / "снимки" / "04_после_set_c7" / "backup.bin"
    _, blob = decoder.read_blob(str(blob_path))
    payload, container, warnings = decoder.split_container(blob)
    candidates = []
    for e in fmap["entries_mode1"]:
        if e.get("segment") != "custom_0x1C00" or e.get("blob_offset") is None:
            continue
        off, size = int(e["blob_offset"], 0), e["size"]
        vals = []
        for slot in range(7):
            pos = off + slot * 0x400
            if pos + size > len(payload):
                vals.append(None)
            else:
                vals.append(int.from_bytes(payload[pos:pos+size], "little", signed=e.get("signed_access", False)))
        if vals == [7] * 7:
            candidates.append({"id": e["ui_setp"], "name": e["name"], "blob_offset_C1": e["blob_offset"], "type": e["type"], "values_C1_C7": vals})

    result = {
        "firmware": "X-H2 5.30",
        "scope": "PTP свойства 0xD18C–0xD1A5 из списка RAW CONV",
        "source_list": {"address": "0x32AEDD0", "count": 61, "slot_range_count": len(properties), "first": "0xD18C", "last": "0xD1A5"},
        "registry": {"main": "0x3443000", "D1A5_entry": "0x344350C", "special_slot_group": "0x3443590", "special_group_codes": "D18E–D197 и D1B0–D1B9", "D1A5_in_special_slot_group": False},
        "descriptor_findings": {"camera_get_device_prop_desc": "0x1014 returned 0x2002 GeneralError and zero bytes for each of D18C–D1A5 in snapshot 04_после_set_c7", "firmware_table_278": {"D18C": PTP_DESC_278[0xD18C], "D18D": PTP_DESC_278[0xD18D]}, "other_defaults": "не установлены из доступного описателя PTP"},
        "properties": properties,
        "d1a5": {
            "finding": "Свойство читается и равно 7 во всех C1–C7, но имя UI_SETP и прямая связь с полем банка не установлены.",
            "handler_search": "В блоке 5.30 b1 точный 32-битный литерал D1A5 найден только в реестре 0x344350C; дизассемблер не нашёл отдельного сравнения с immediate 0xD1A5.",
            "bank_candidates_equal_7": candidates,
            "interpretation": "Совпадение значения 7 не доказывает связь: в слотовом банке два несвязанных по смыслу кандидата, UI_SETP_FOCUS_90 и UI_SETP_FOCUS_270, оба равны 7 во всех слотах. D1A5 отсутствует в fujicli option.cue и в выделенной группе 0x3443590.",
            "value_C1_C7": {slot: 7 for slot in slots},
            "backup_container": container,
            "backup_warnings": warnings,
        },
        "sources": [
            "PTP_чтение_2026-11-10/Связь_USB_и_прошивки.md",
            "Сравнение_версий_2026-11-16/blocks/X-H2_5.30_b1_0x840274.bin",
            "Камера_2026-11-17/K2_прошивка/карта_банка.tsv и карта_банка.json",
            "fujicli_2026-11-18/C2_модель_камеры/сопоставление.json; Внешние_репозитории/fujicli/fml/option.cue",
            "fujicli_2026-11-18/совместимость/снимки/04_после_set_c7/snapshot.json и backup.bin",
            "локальная таблица 278 свойств из полных_отчётов/Чтение_камеры_по_USB/Таблица_278_свойств_из_прошивки.tsv (D18C/D18D)",
        ],
    }
    (OUT / "результат.json").write_text(json.dumps(result, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")
    lines = [
        "# Z2: свойство 0xD1A5 и карта слотов X-H2 5.30", "",
        "## Выводы", "",
        "1. Список RAW CONV по адресу `0x32AEDD0` содержит 61 код; диапазон `0xD18C–0xD1A5` в нём представлен всеми 26 кодами подряд.",
        "2. Код `0x3443000` — реестр кодов Fuji-свойств. В нём `0xD1A5` находится по адресу `0x344350C`; выделенная группа слотов начинается по `0x3443590` и содержит `D18E–D197` и `D1B0–D1B9`, но не `D1A5`.",
        "3. Для `D18C` и `D18D` есть строки в прежней таблице 278 свойств. Для `D18E–D1A5` PTP-описатель не получен: запрос `GetDevicePropDesc (0x1014)` в снимке камеры вернул `0x2002 GeneralError` и 0 байт. Поэтому значения по умолчанию для этих кодов не подменены текущими значениями слотов.",
        "4. `D1A5` читается как `0x0007` во всех C1–C7 в наборе наблюдений. Ни `fujicli option.cue`, ни выделенная группа слотов прошивки не задают ему имя или связь с UI_SETP.",
        "5. В резервной копии два поля `UI_SETP_FOCUS_90` (`0x6FC`) и `UI_SETP_FOCUS_270` (`0x6FD`) имеют значение 7 во всех семи слотах. Это численное совпадение, но доказательства связи с `D1A5` нет; называть какое-либо поле соответствующим `D1A5` нельзя.",
        "6. В блоке 5.30 b1 точный 32-битный код `D1A5` найден только в реестре `0x344350C`; отдельной инструкции сравнения с immediate `0xD1A5` дизассемблер не обнаружил. Этот поиск не заменяет разбор всех косвенных путей обработки.",
        "7. Для `D18D–D1A4` имена и допустимые значения в таблице сверены с fujicli. Переводы кодов через таблицы поиска, масштабирование и составные поля UI_SETP перечислены в примечаниях после таблицы.",
        "",
        "Уровни: **Д** — прямое совпадение таблиц/наблюдений; **К** — сильное смысловое сопоставление значения USB с полем UI_SETP; «не найдено» — не выдаётся за доказанную связь.",
        "",
        "## Карта свойств", "",
        "Значение по умолчанию берётся из строки PTP-описания, если она есть. Для остальных свойств указано «не опубликовано»: доступный запрос 0x1014 возвращал ошибку. Диапазоны и значения в последнем столбце — схема fujicli, а не утверждение о PTP-описателе прошивки.",
        "",
        "| Код | Внутренний номер → имя UI_SETP | Тип ответа | Доступ, проверенный здесь | Форма и значения fujicli | По умолчанию PTP | Сопоставление |",
        "|---|---|---|---|---|---|---|",
    ]
    for p in properties:
        c = int(p["code"], 16)
        internals = "; ".join(f"`{x['id']}` `{x['name']}` ({x['confidence']})" for x in p["internal_settings"]) or "не установлено"
        vals = p["domain_fujicli"].replace("|", "\\|")
        form = p["form"]
        lines.append(f"| `{p['code']}` | {internals} | {p['ptp_type']} | {p['access']} | {form}: {vals} | {p['default_from_descriptor'] or 'не опубликовано'} | {p['mapping_level']} |")
    lines += [
        "", "## Что означает D1A5=7", "",
        "В снимке 04 код `D1A5` имеет двухбайтовое значение `07 00`; таблица слотов по fujicli показывает 7 для C1–C7. Проверка копии BACKUP по карте `mode1` нашла два поля, равные 7 во всех слотах: `UI_SETP_FOCUS_90` и `UI_SETP_FOCUS_270`. Их связь с USB-кодом `D1A5` не подтверждена; оба не являются достаточным объяснением без обращения к коду чтения/записи D1A5.",
        "",
        "Следовательно, ответ на вопрос о соответствующем поле банка пока отрицательный: однозначно связанное поле не найдено, и совпадение с 7 не позволяет объявить его совпадением с наблюдением. Чтобы связать код с полем, нужен статический путь обработчика D1A5 (или независимый набор резервных копий с однофакторно различающимся значением после подтверждённой операции; камеру в рамках этой задачи не трогали).",
        "",
        "## Сверка с fujicli и наблюдениями", "",
        "- `D18C` — выбор C1–C7, внутренний `UI_SETP_CUSTOM_SET_SAVE` (`0xDC`); `D18D` — строковое имя, `UI_SETP_CUSTOM_SAVE_NAME` (`0x730`). Их тип, доступ, форма и значение по умолчанию совпадают с таблицей 278.",
        "- `D18E–D1A4` совпадают по смыслу и спискам/диапазонам с `option.cue`. Для `D195` fujicli описывает 6/7 как варианты чтения Off с сохранённым размером; на X-H2 запись 0x06 наблюдалась с отказом `0x201C`, а запись 0x01 была принята.",
        "- Значения USB и поля банка нельзя в целом приравнивать: `D18E`, `D18F`, `D190`, `D191`, `D192`, `D195` и `D1A1` используют коды выбора/таблицы; `D193`, `D194`, `D19D`, `D19E`, `D19F`, `D1A0`, `D1A2` используют масштаб x10; `D19C` — температура с шагом 10; `D18E` и `D195` сводят несколько внутренних полей/сохранённое состояние в одно USB-значение.",
        "- Сопоставления D18E–D1A4 в колонке UI_SETP — смысловые связи по имени опции и карте банка (уровень К); несколько кодов представляют составное или зависящее от выбранного режима значение. Для D19A/B внутреннее значение формируется семейством настроек баланса белого, поэтому одна запись UI_SETP не описывает все сохранённые варианты WB.",
        "- `D1A5` отсутствует в fujicli и не входит в выделенную группу `0x3443590`; только наличие кода в списке 61 и значение 7 подтверждены.",
        "",
        "## Что это даёт для будущих доработок прошивки", "",
        "1. Для чтения/записи слотов следует использовать отдельную таблицу преобразования USB-кодов в UI_SETP, а не копировать коды напрямую в банк.",
        "2. Связь для `D1A5` остаётся открытой. Пока не найден маршрут его диспетчеризации, нельзя изменять поле банка, исходя только из равенства значения 7.",
        "3. Значение по умолчанию для новых свойств следует брать из подтверждённого кода инициализации/описателя; текущее содержимое C1–C7 не является доказательством default.",
        "",
        "## Воспроизведение и источники", "",
        "Запустить `python build_result.py` из этой папки. Скрипт читает прошивочные блоки через `fwcommon`, карту банка, один резервный образ и локальные результаты fujicli; записывает только `результат.json` и `отчёт.md` в папку Z2.",
        "",
        "Адреса и материалы: `Связь_USB_и_прошивки.md`; блок 5.30 `X-H2_5.30_b1_0x840274.bin`; таблица 278 свойств из локального каталога `полные_отчёты/Чтение_камеры_по_USB`; `карта_банка.tsv/.json`; `option.cue`; `snapshot.json`; `слоты_по_fujicli.json`; `backup.bin` в снимке `04_после_set_c7`.",
    ]
    (OUT / "отчёт.md").write_text("\n".join(lines) + "\n", encoding="utf-8")


if __name__ == "__main__":
    main()
