"""Офлайн-проверка совместимости слотов X-H2 со схемой fujicli (X-T5).
Вход: сырой лог чтения слотов (PTP 0x1015), только чтение файлов.
Таблицы кодировок пересказаны из fujicli fml/option.cue (27d3a6b), пределы — из _pins X-T5 (fml/camera.cue)."""
import re, sys, json, struct

def lk(d):  # name->code  =>  code->name
    r = {}
    for k, v in d.items():
        for c in (v if isinstance(v, list) else [v]):
            r[c] = k
    return r

LOOKUP = {
    0xD18E: ("image_size", lk({"l_3_2":7,"l_16_9":8,"l_1_1":9,"l_4_3":0xe,"l_5_4":0x10,"m_3_2":4,"m_16_9":5,"m_1_1":6,
                                "m_4_3":0x12,"m_5_4":0x14,"s_3_2":1,"s_16_9":2,"s_1_1":3,"s_4_3":0xa,"s_5_4":0xc})),
    0xD18F: ("image_quality", lk({"fine_raw":4,"fine":2,"normal_raw":5,"normal":3,"raw":1})),
    0xD190: ("dynamic_range", lk({"auto":0xffff,"hdr100":0x64,"hdr200":0xc8,"hdr400":0x190,"hdr800":0x320,"hdr800_plus":0x640})),
    0xD191: ("dynamic_range_priority", lk({"auto":0x8000,"plus":3,"strong":2,"weak":1,"off":0})),
    0xD192: ("film_simulation", lk({"provia":1,"velvia":2,"astia":3,"pro_neg_hi":4,"pro_neg_std":5,"monochrome":6,"monochrome_ye":7,
              "monochrome_r":8,"monochrome_g":9,"sepia":0xa,"classic_chrome":0xb,"acros":0xc,"acros_ye":0xd,"acros_r":0xe,
              "acros_g":0xf,"eterna":0x10,"classic_negative":0x11,"eterna_bleach_bypass":0x12,"nostalgic_negative":0x13,"reala_ace":0x14})),
    0xD195: ("grain_effect", lk({"strong_large":5,"weak_large":4,"strong_small":3,"weak_small":2,"off":[1,6,7]})),
    0xD196: ("color_chrome_effect", lk({"strong":3,"weak":2,"off":1})),
    0xD197: ("color_chrome_fx_blue", lk({"strong":3,"weak":2,"off":1})),
    0xD198: ("smooth_skin_effect", lk({"strong":3,"weak":2,"off":1})),
    0xD199: ("white_balance", lk({"as_shot":0,"white_priority":0x8020,"auto":2,"ambience_priority":0x8021,"custom1":0x8008,
              "custom2":0x8009,"custom3":0x800a,"temperature":0x8007,"daylight":4,"shade":0x8006,"fluorescent1":0x8001,
              "fluorescent2":0x8002,"fluorescent3":0x8003,"incandescent":6,"underwater":8})),
    0xD1A1: ("noise_reduction", lk({"4":0x5000,"3":0x6000,"2":0,"1":0x1000,"0":0x2000,"-1":0x3000,"-2":0x4000,"-3":0x7000,"-4":0x8000})),
    0xD1A3: ("lens_modulation_optimizer", lk({"on":1,"off":2})),
    0xD1A4: ("color_space", lk({"srgb":1,"adobe_rgb":2})),
}
# (имя, делитель, min, max, step) — пределы X-T5
SCALE = {
    0xD193: ("monochromatic_color_temperature", 10, -18, 18, 1),
    0xD194: ("monochromatic_color_tint", 10, -18, 18, 1),
    0xD19A: ("white_balance_shift_red", 1, -9, 9, 1),
    0xD19B: ("white_balance_shift_blue", 1, -9, 9, 1),
    0xD19C: ("white_balance_temperature", 1, 2500, 10000, 10),
    0xD19D: ("highlight_tone", 10, -2.0, 4.0, 0.5),
    0xD19E: ("shadow_tone", 10, -2.0, 4.0, 0.5),
    0xD19F: ("color", 10, -4, 4, 1),
    0xD1A0: ("sharpness", 10, -4, 4, 1),
    0xD1A2: ("clarity", 10, -5, 5, 1),
}
MONO = {"monochrome","monochrome_ye","monochrome_r","monochrome_g","sepia","acros","acros_ye","acros_r","acros_g"}

def name_of(hexdata):
    b = bytes.fromhex(hexdata); n = b[0]
    return b[1:1+2*n].decode("utf-16le").rstrip("\0")

slots, cur = {}, None
for line in open(sys.argv[1], encoding="utf-8", errors="replace"):
    m = re.match(r"C(\d) 0x([0-9A-F]{4}) resp 0x(\w+) data (\w*)", line.strip())
    if m:
        s, code, resp, data = int(m[1]), int(m[2], 16), m[3], m[4]
        slots.setdefault(s, {})[code] = (resp, data)

report = {"slots": {}, "unknown_props": set(), "issues": []}
for s in sorted(slots):
    out = {}
    for code, (resp, data) in sorted(slots[s].items()):
        key = f"0x{code:04X}"
        if code == 0xD18D:
            out[key] = ("custom_setting_name", name_of(data)); continue
        raw = bytes.fromhex(data)
        u = int.from_bytes(raw, "little"); i = int.from_bytes(raw, "little", signed=True)
        if code in LOOKUP:
            nm, tab = LOOKUP[code]
            v = tab.get(u)
            out[key] = (nm, v if v is not None else f"НЕИЗВЕСТНО 0x{u:X}")
            if v is None: report["issues"].append(f"C{s} {nm}: код 0x{u:X} отсутствует в таблице fujicli")
        elif code in SCALE:
            nm, div, lo, hi, st = SCALE[code]
            v = i / div if div != 1 else i
            ok = lo <= v <= hi and abs((v - lo) / st - round((v - lo) / st)) < 1e-9
            out[key] = (nm, v)
            if not ok: report["issues"].append(f"C{s} {nm}: {v} вне пределов X-T5 [{lo}..{hi}, шаг {st}]")
        else:
            out[key] = ("нет в fujicli", f"0x{u:X}"); report["unknown_props"].add(key)
    fs = dict(out.values()).get("film_simulation")
    if fs not in MONO:
        for k in ("monochromatic_color_temperature","monochromatic_color_tint"):
            if dict(out.values()).get(k) not in (0, 0.0, None):
                report["issues"].append(f"C{s} {k} ≠ 0 при цветной плёнке {fs}")
    report["slots"][f"C{s}"] = out

report["unknown_props"] = sorted(report["unknown_props"])
names = [v[0] for v in next(iter(report["slots"].values())).values()]
print("поле".ljust(34) + "".join(f"C{s}".ljust(22) for s in sorted(slots)))
for idx, key in enumerate(next(iter(report["slots"].values())).keys()):
    row = f"{key} {names[idx]}"[:33].ljust(34)
    row += "".join(str(report["slots"][f"C{s}"].get(key, ("", "—"))[1])[:21].ljust(22) for s in sorted(slots))
    print(row)
print("\nСвойства вне схемы fujicli:", report["unknown_props"])
print("Замечания:", report["issues"] or "нет")
json.dump(report, open(sys.argv[2], "w", encoding="utf-8"), ensure_ascii=False, indent=1, default=str)
