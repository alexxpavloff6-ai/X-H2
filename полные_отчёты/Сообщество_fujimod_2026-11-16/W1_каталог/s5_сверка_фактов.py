# -*- coding: utf-8 -*-
"""Сверка числовых фактов каталога fujimod с нашими DAT/блоками.

Проверяем:
  1) settings.source.sha256 == sha256 нашего распакованного блока 0;
  2) bulk.window == база/размер блока 1 (старший ARM64);
  3) flash.update_image (dat_offset 628, xor 255) действительно даёт их «образ флеша»
     — сверяем flash.control.sha256;
  4) restart.code_checks / flash.code_ranges: адрес -> блок -> sha256 фрагмента;
  5) identity: update.sha256 == sha256 нашего DAT.
Всё только чтение; пишет s5_сверка_фактов.json."""
import hashlib, json, os, sys
sys.stdout.reconfigure(encoding="utf-8")

ROOT = r"<корень проекта>"
CAT = r"<корень проекта>\Внешние_репозитории\fujimod\catalog\firmware"
BLK = os.path.join(ROOT, r"Анализ_прошивки\Сравнение_версий_2026-11-16\blocks")
HERE = os.path.dirname(os.path.abspath(__file__))

DAT = {
    "X-H2": r"FIRMWARE\ver 5.30\FWUP0028.DAT",
    "X-H2S": r"Firmware на прочиеFuji\FWUP0027.DAT",
    "X-T5": r"Firmware на прочиеFuji\FWUP0030.DAT",
}
CASES = [
    # модель, каталог, файлы блоков (пути), базы
    ("X-H2", "xh2/5.30", {
        "b0": ("X-H2_5.30_b0_0x300274.bin", 0x1101000),
        "b1": ("X-H2_5.30_b1_0x840274.bin", 0x29ae000),
        "b2": ("X-H2_5.30_b2_0xf40274.bin", 0x0),
    }),
    ("X-H2S", "xh2s/7.30", {
        "b0": ("X-H2S_7.30_b0_0x300274.bin", 0x1421000),
        "b1": ("X-H2S_7.30_b1_0x840274.bin", 0x2cca000),
        "b2": ("X-H2S_7.30_b2_0xf20274.bin", 0x0),
    }),
    ("X-T5", "xt5/4.31", {
        "b0": ("X-T5_4.31_b0_0x300274.bin", 0x1101000),
        "b1": ("X-T5_4.31_b1_0x820274.bin", 0x28eb000),
        "b2": ("X-T5_4.31_b2_0xf20274.bin", 0x0),
    }),
]

def sha(b):
    return hashlib.sha256(b).hexdigest()

def load_cat(cam, name):
    p = os.path.join(CAT, cam.replace("/", "\\"), name)
    return json.load(open(p, encoding="utf-8")) if os.path.exists(p) else None

def find_block(blocks, addr, size):
    """Блок, в который попадает [addr, addr+size)."""
    for key, (fname, base) in blocks.items():
        data = open(os.path.join(BLK, fname), "rb").read()
        if base <= addr and addr + size <= base + len(data):
            return key, data, base
    return None, None, None

out = {"случаи": []}
for model, cam, blocks in CASES:
    rec = {"модель": model, "каталог": cam, "проверки": []}
    print("=" * 70)
    print(model, cam)
    fw = load_cat(cam, "firmware.json")
    if fw:
        dat = open(os.path.join(ROOT, DAT[model]), "rb").read()
        ok = sha(dat) == fw["update"]["sha256"]
        rec["проверки"].append({"что": "update.sha256 == sha256 нашего DAT",
                                "ожидалось": fw["update"]["sha256"], "получено": sha(dat),
                                "совпало": ok})
        print("  identity: update.sha256 == DAT ?", ok, "| размер", fw["update"]["size"], "==", len(dat))

    st = load_cat(cam, "settings.generated.json")
    if st:
        b0 = open(os.path.join(BLK, blocks["b0"][0]), "rb").read()
        ok = sha(b0) == st["source"]["sha256"]
        rec["проверки"].append({"что": "settings.source.sha256 == sha256 нашего блока 0",
                                "ожидалось": st["source"]["sha256"], "получено": sha(b0), "совпало": ok})
        print("  settings.source: адрес 0x%X (база b0 0x%X) размер %d (b0 %d) sha==наш b0 ? %s" % (
            st["source"]["address"], blocks["b0"][1], st["source"]["size"], len(b0), ok))
        rec["проверки"][-1]["адрес"] = st["source"]["address"]
        rec["проверки"][-1]["база_b0"] = blocks["b0"][1]
        rec["проверки"][-1]["размер"] = st["source"]["size"]
        rec["проверки"][-1]["размер_b0"] = len(b0)

    bulk = load_cat(cam, "bulk.generated.json")
    if bulk:
        b1f, b1base = blocks["b1"]
        b1 = open(os.path.join(BLK, b1f), "rb").read()
        win = bulk["window"]
        ok = win["address"] == b1base and win["size"] == len(b1)
        rec["проверки"].append({"что": "bulk.window == база/размер блока 1",
                                "окно": [win["address"], win["size"]], "блок1": [b1base, len(b1)], "совпало": ok})
        print("  bulk.window 0x%X+0x%X vs блок1 0x%X+0x%X -> %s" % (
            win["address"], win["size"], b1base, len(b1), ok))
        print("    mechanism=%s registered_buffer=0x%X source_state=0x%X configuration_pointer=0x%X configuration_bytes=0x%X system_mode_address=0x%X capacity=0x%X" % (
            bulk["source"]["mechanism"], bulk["source"]["registered_buffer"], bulk["source"]["source_state"],
            bulk["source"]["configuration_pointer"], bulk["source"]["configuration_bytes"],
            bulk["source"]["system_mode_address"], bulk["source"]["capacity"]))
        rec["bulk_source"] = bulk["source"]

    fl = load_cat(cam, "flash.generated.json")
    if fl:
        dat = open(os.path.join(ROOT, DAT[model]), "rb").read()
        dec = bytes(b ^ 0xFF for b in dat[fl["update_image"]["dat_offset"]:])
        c = fl["control"]
        got = sha(dec[c["offset"]:c["offset"] + c["size"]])
        ok = got == c["sha256"]
        rec["проверки"].append({"что": "flash: control-чанк из (DAT[628:] xor FF)",
                                "ожидалось": c["sha256"], "получено": got, "совпало": ok})
        print("  flash.control offset=0x%X size=0x%X: (DAT[0x%X:]^FF) -> %s" % (
            c["offset"], c["size"], fl["update_image"]["dat_offset"], ok))
        for cr in fl["code_ranges"]:
            key, data, base = find_block(blocks, cr["address"], cr["size"])
            if key is None:
                print("    %-42s 0x%08X +%d -> блок не найден" % (cr["name"], cr["address"], cr["size"]))
                continue
            frag = sha(data[cr["address"] - base: cr["address"] - base + cr["size"]])
            print("    %-42s 0x%08X +%-4d -> %s  sha=%s" % (cr["name"], cr["address"], cr["size"], key, frag[:16]))
            rec.setdefault("code_ranges", []).append({"name": cr["name"], "address": cr["address"],
                                                      "size": cr["size"], "block": key, "sha256": frag})
        for ck in fl.get("state_checks", []):
            print("    state_check %-28s 0x%08X value=%d (рантайм-RAM, в DAT нет)" % (
                ck["name"], ck["address"], ck["value"]))
        rec["flash_device"] = fl["device"]
        rec["flash_window"] = fl["window"]

    rs = load_cat(cam, "restart.generated.json")
    if rs:
        print("  restart: internal_version=%s механизм=%s" % (rs.get("internal_version"), rs["mechanism"]["transport"]["kind"]))
        for ck in rs.get("code_checks", []):
            key, data, base = find_block(blocks, ck["address"], ck["size"])
            if key is None:
                print("    %-28s 0x%08X +%d -> блок не найден" % (ck["name"], ck["address"], ck["size"]))
                rec.setdefault("restart_checks", []).append({"name": ck["name"], "address": ck["address"],
                                                             "size": ck["size"], "block": None,
                                                             "совпало": None})
                continue
            frag = sha(data[ck["address"] - base: ck["address"] - base + ck["size"]])
            ok = frag == ck["sha256"]
            print("    %-28s 0x%08X +%-4d -> %s sha==их ? %s" % (ck["name"], ck["address"], ck["size"], key, ok))
            rec.setdefault("restart_checks", []).append({"name": ck["name"], "address": ck["address"],
                                                         "size": ck["size"], "block": key,
                                                         "их_sha256": ck["sha256"], "наш_sha256": frag,
                                                         "совпало": ok})

    out["случаи"].append(rec)

json.dump(out, open(os.path.join(HERE, "s5_сверка_фактов.json"), "w", encoding="utf-8"),
          ensure_ascii=False, indent=2)
print("\nсохранено: s5_сверка_фактов.json")
