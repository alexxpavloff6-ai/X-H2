"""Extract film-simulation and image-setting enum dictionaries from X-H2 5.30.
Reads the supplied DAT and reuses the verified local FFLZ decoder.
Does not modify/repack firmware, access a camera or infer colour-processing coefficients.
"""
from pathlib import Path
import csv
import hashlib
import importlib.util
import json
import re
import struct

HERE = Path(__file__).resolve().parent
PARENT = HERE.parent
spec = importlib.util.spec_from_file_location("xh2_readonly", PARENT / "анализ_файла.py")
previous = importlib.util.module_from_spec(spec)
spec.loader.exec_module(previous)

def digest(data):
    return hashlib.sha256(data).hexdigest()

def read_name(block, offset):
    if not 0 <= offset < len(block):
        return None
    end = block.find(b"\0", offset, min(offset+150, len(block)))
    if end < 0:
        return None
    word = block[offset:end]
    if not re.fullmatch(rb"[A-Za-z][A-Za-z0-9_.]{3,140}", word):
        return None
    return word.decode("ascii")

def write_table(name, header, rows):
    with (HERE / name).open("w", encoding="utf-8-sig", newline="") as output:
        writer = csv.writer(output, delimiter="\t", lineterminator="\n")
        writer.writerow(header)
        writer.writerows(rows)

# These labels translate explicit firmware names; aliases F1B/F1C/F2 and SUPERIA
# are deliberately left unresolved rather than mapped by their table order.
PUBLIC_NAMES = {
    "UI_FILM_SIM_STD": "Стандартная имитация (STD)",
    "UI_FILM_SIM_SEPIA": "Сепия",
    "UI_FILM_SIM_BW_FILTER_NON": "Монохром без цветного фильтра",
    "UI_FILM_SIM_BW_FILTER_R": "Монохром с красным фильтром",
    "UI_FILM_SIM_BW_FILTER_Y": "Монохром с жёлтым фильтром",
    "UI_FILM_SIM_BW_FILTER_G": "Монохром с зелёным фильтром",
    "UI_FILM_SIM_PRONEGA_S": "PRO Neg. Std, по названию",
    "UI_FILM_SIM_PRONEGA_H": "PRO Neg. Hi, по названию",
    "UI_FILM_SIM_CLASSIC_CHROME": "Classic Chrome",
    "UI_FILM_SIM_REALA": "REALA",
    "UI_FILM_SIM_ETERNA": "ETERNA",
    "UI_FILM_SIM_BLEACH_BYPASS": "ETERNA BLEACH BYPASS, по названию",
    "UI_FILM_SIM_ACROS_FILTER_NON": "ACROS без цветного фильтра",
    "UI_FILM_SIM_ACROS_FILTER_R": "ACROS с красным фильтром",
    "UI_FILM_SIM_ACROS_FILTER_Y": "ACROS с жёлтым фильтром",
    "UI_FILM_SIM_ACROS_FILTER_G": "ACROS с зелёным фильтром",
}
FAMILIES = {
    "чёткость": r"UI_CLARITY_",
    "светлые_участки": r"UI_HIGHLIGHT_",
    "тёмные_участки": r"UI_SHADOW_",
    "сдвиг_баланса_белого": r"UI_WB_TUNING_(?:R|B)_",
    "тонирование_монохрома": r"UI_BLACK_TONE_(?:(?:RG_)?(?:P|M)?\d+$)",
    "динамический_диапазон": r"UI_DRANGE_(?:AUTO|\d+)$",
    "цвет": r"UI_STILLCOLOR_",
    "резкость": r"UI_SHARPNESS_",
    "шумоподавление": r"UI_NR_",
    "зерно": r"UI_(?:GRAIN_|Q_GRAIN_)",
    "эффекты_цвета_внутренние_названия": r"UI_(?:SHADOWING|BLUE_EFFECT)_",
    "баланс_белого": r"UI_WB_(?!TUNING_)[A-Z0-9_]+$",
}
SETTING_NAMES = {
    "UI_SETP_FILM_SIM", "UI_SETP_FILM_SIM_ACROS", "UI_SETP_FILM_SIM_MONO",
    "UI_SETP_WB", "UI_SETP_WB_TUNING_R", "UI_SETP_WB_TUNING_B",
    "UI_SETP_NR", "UI_SETP_CLARITY", "UI_SETP_DRANGE", "UI_SETP_STILLCOLOR",
    "UI_SETP_SHARPNESS", "UI_SETP_HIGHLIGHT", "UI_SETP_SHADOW",
    "UI_SETP_GRAIN", "UI_SETP_GRAIN_SIZE",
    "UI_SETP_SHADOWING", "UI_SETP_BLUE_EFFECT",
}

def explicit_number(name):
    match = re.search(r"_(P|M)?(\d+(?:p\d+)?)$", name)
    if not match:
        return "", "Название не задаёт числовую величину"
    value = float(match.group(2).replace("p", "."))
    if match.group(1) == "M":
        value = -value
    # For DR100 etc the suffix is a named option; keep it separate from signed scales.
    if name.startswith("UI_DRANGE_"):
        return str(int(value)), "Число в названии варианта; не коэффициент обработки"
    return f"{value:g}", "Число явно записано в обозначении; доступность проверяется отдельно"

def main():
    raw = previous.SOURCE.read_bytes()
    assert digest(raw) == previous.EXPECTED_SHA256
    meta = json.loads((PARENT / "сведения.json").read_text(encoding="utf-8"))
    decoded = raw.translate(previous.TRANSLATION)
    block_offset = 0x840274
    block = previous.unpack_fflz(decoded, block_offset)
    expected = next(x for x in meta["fflz_blocks"] if int(x["file_offset"],16) == block_offset)
    assert digest(block) == expected["decoded_sha256"]
    base = struct.unpack_from("<Q", block, 8)[0]
    assert base == 0x029ae000
    records = []
    # Scan aligned name-pointer / uint64-value pairs, retaining only valid names
    # and small enum values. Individual exported groups are checked below.
    for pos in range(0, len(block)-16, 8):
        pointer, value = struct.unpack_from("<QQ", block, pos)
        if value > 0xffff:
            continue
        name = read_name(block, pointer-base)
        if name:
            records.append({
                "record_offset": pos, "string_offset": pointer-base,
                "pointer": pointer, "value": value, "name": name,
            })
    std = next(row for row in records if row["name"] == "UI_FILM_SIM_STD")
    start = std["record_offset"]
    by_offset = {row["record_offset"]: row for row in records}
    film = [by_offset[start+i*16] for i in range(26)]
    assert [row["value"] for row in film] == list(range(26))
    assert all(row["name"].startswith("UI_FILM_SIM_") for row in film)
    assert film[14]["name"] == "UI_FILM_SIM_CLASSIC_CHROME"
    assert film[17]["name"] == "UI_FILM_SIM_REALA"
    selected, setting_ids = [], []
    for row in records:
        if row["name"] in SETTING_NAMES:
            setting_ids.append(row)
        for family, pattern in FAMILIES.items():
            if re.match(pattern, row["name"]):
                selected.append({**row, "family": family})
                break
    # Independent endpoint and neutral-value checks from raw dictionary entries.
    by_name = {row["name"]: row["value"] for row in records}
    assert [by_name["UI_CLARITY_"+x] for x in ("P5","0","M5")] == [0,5,10]
    assert [by_name["UI_HIGHLIGHT_"+x] for x in ("P4","0","M2")] == [0,8,12]
    assert [by_name["UI_SHADOW_"+x] for x in ("P4","0","M2")] == [0,8,12]
    assert by_name["UI_WB_TUNING_R_0"] == by_name["UI_WB_TUNING_B_0"] == 9
    assert by_name["UI_GRAIN_HIGH"] == 0 and by_name["UI_GRAIN_OFF"] == 2
    write_table("Имитации_плёнки.tsv",
        ["код_перечисления","код_16ричный","внутреннее_обозначение","пояснение_по_названию","смещение_записи_в_распакованном_блоке","смещение_строки_в_блоке"],
        [(r["value"],hex(r["value"]),r["name"],PUBLIC_NAMES.get(r["name"],"Требуется проверка назначения и доступности"),hex(r["record_offset"]),hex(r["string_offset"])) for r in film])
    write_table("Настройки_изображения.tsv",
        ["группа","код_перечисления","внутреннее_обозначение","число_из_названия","предел_толкования","смещение_записи_в_блоке"],
        [(r["family"],r["value"],r["name"],*explicit_number(r["name"]),hex(r["record_offset"])) for r in selected])
    write_table("Коды_параметров.tsv",
        ["внутреннее_обозначение","код_параметра","код_16ричный","смещение_записи_в_блоке"],
        [(r["name"],r["value"],hex(r["value"]),hex(r["record_offset"])) for r in setting_ids])
    hex_lines = []
    for row in film:
        pos = row["record_offset"]
        hex_lines.append(f'{pos:08X}  {block[pos:pos+16].hex(" ")}  {row["name"]} = {row["value"]}')
    (HERE / "Исходные_записи_таблицы.txt").write_text("\n".join(hex_lines)+"\n",encoding="utf-8")
    result = {
        "source": str(previous.SOURCE), "source_sha256": digest(raw),
        "packed_block_file_offset": hex(block_offset), "decoded_block_sha256": digest(block),
        "header_address_basis": hex(base), "record_shape": "u64 name_pointer, u64 enumeration_value, little endian",
        "film_dictionary_start": hex(start), "film_dictionary_records": len(film),
        "related_setting_values": len(selected), "setting_id_records": len(setting_ids),
        "film_simulations": film, "setting_ids": setting_ids,
        "family_counts": {f:sum(r["family"]==f for r in selected) for f in FAMILIES},
        "raw_to_named_examples": {
            "UI_CLARITY_0":by_name["UI_CLARITY_0"],
            "UI_HIGHLIGHT_0":by_name["UI_HIGHLIGHT_0"],
            "UI_SHADOW_0":by_name["UI_SHADOW_0"],
            "UI_WB_TUNING_R_0":by_name["UI_WB_TUNING_R_0"],
            "UI_WB_TUNING_B_0":by_name["UI_WB_TUNING_B_0"],
            "UI_GRAIN_OFF":by_name["UI_GRAIN_OFF"],
        },
        "limits": [
            "Enum dictionary codes are not image-processing coefficients.",
            "Dictionary presence does not prove availability on this camera.",
            "This does not identify firmware storage layout or USB/EXIF protocol codes.",
            "No per-film colour LUTs, tone curves or factory preset bundles have been established.",
        ],
        "input_unchanged": digest(previous.SOURCE.read_bytes()) == digest(raw),
    }
    assert result["input_unchanged"]
    (HERE / "Доказательства_извлечения.json").write_text(json.dumps(result,ensure_ascii=False,indent=2)+"\n",encoding="utf-8")
    print(json.dumps({k:result[k] for k in ["film_dictionary_records","related_setting_values","setting_id_records","family_counts","input_unchanged"]},ensure_ascii=True,indent=2))

if __name__ == "__main__":
    main()
