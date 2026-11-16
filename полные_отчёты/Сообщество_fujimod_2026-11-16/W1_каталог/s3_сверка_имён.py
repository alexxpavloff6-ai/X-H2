# -*- coding: utf-8 -*-
"""Сверка таблиц имён fujimod (catalog/firmware/<cam>/<ver>/ui-*-names.generated.json)
с именами, которые мы сами собрали из блоков наших DAT
(Сравнение_версий_2026-11-16/F_режим_съёмки/strings/*.txt).

Только чтение. Пишет s3_сверка_имён.json и печатает сводку."""
import json, os, re, sys
sys.stdout.reconfigure(encoding="utf-8")

CAT = r"<корень проекта>\Внешние_репозитории\fujimod\catalog\firmware"
OURS = r"<корень проекта>\Анализ_прошивки\Сравнение_версий_2026-11-16\F_режим_съёмки\strings"
HERE = os.path.dirname(os.path.abspath(__file__))

CAMS = [
    # (наш префикс файлов, каталог fujimod, наша версия, версия fujimod)
    ("XH2_5.30", "xh2/5.30", "5.30", "5.30"),
    ("XH2_5.33", "xh2/5.30", "5.33", "5.30"),      # у fujimod нет 5.33 -> сверяем с 5.30
    ("XH2S_7.30", "xh2s/7.30", "7.30", "7.30"),
    ("XH2S_7.31", "xh2s/7.30", "7.31", "7.30"),
    ("XT5_4.31", "xt5/4.31", "4.31", "4.31"),
    ("XT5_4.32", "xt5/4.31", "4.32", "4.31"),
]

def our_names(prefix, kind):
    """Множество имён нужного вида из наших строковых дампов блоков 0 и 1."""
    rx = re.compile(r"^(UI_SETP_[A-Za-z0-9_]+|UILIB_[A-Za-z0-9_]+)$")
    out = {}
    for b in ("b0", "b1"):
        p = os.path.join(OURS, "%s_%s.txt" % (prefix, b))
        if not os.path.exists(p):
            continue
        with open(p, encoding="utf-8", errors="replace") as f:
            for line in f:
                line = line.rstrip("\n")
                if "\t" not in line:
                    continue
                addr, s = line.split("\t", 1)
                if not rx.match(s):
                    continue
                if kind == "settings" and not s.startswith("UI_SETP_"):
                    continue
                if kind == "scene" and not s.startswith("UILIB_"):
                    continue
                out.setdefault(s, addr)
    return out

def fuji_names(cam, ver, fname):
    p = os.path.join(CAT, cam.replace("/", "\\"), fname)
    j = json.load(open(p, encoding="utf-8"))
    key = "ui_setting_names" if "setting" in fname else "ui_scene_names"
    return j, j[key]

report = {"камеры": []}
for prefix, cam, ourver, fujiver in CAMS:
    for kind, fname in (("settings", "ui-setting-names.generated.json"),
                        ("scene", "ui-scene-names.generated.json")):
        fj, fuji = fuji_names(cam, fujiver, fname)
        ours = our_names(prefix, kind)
        common = sorted(set(fuji) & set(ours))
        only_fuji = sorted(set(fuji) - set(ours))
        only_ours = sorted(set(ours) - set(fuji))
        rec = {
            "наши_файлы": prefix,
            "наша_версия": ourver,
            "fujimod": cam + " " + fujiver,
            "вид": kind,
            "имён_у_fujimod": len(fuji),
            "имён_у_нас": len(ours),
            "общих": len(common),
            "только_fujimod": len(only_fuji),
            "только_у_нас": len(only_ours),
            "примеры_только_fujimod": only_fuji[:12],
            "примеры_только_у_нас": only_ours[:12],
            "sha_в_нашем_dat": fj.get("firmware_sha256"),
        }
        report["камеры"].append(rec)
        print("%-12s %-8s %-6s fujimod=%4d наши=%4d общих=%4d толькоF=%3d толькоO=%4d" % (
            prefix, kind, fujiver, len(fuji), len(ours), len(common), len(only_fuji), len(only_ours)))
        if only_fuji[:8]:
            print("    только у fujimod:", only_fuji[:8])

# ключевые ID из наших отчётов
KNOWN = {
    # имя: {модель: (наш ID из наших отчётов, источник)}
    "UI_SETP_FILM_SIM": {"xh2": 1678, "xh2s": None, "xt5": 1699},
    "UI_SETP_STILLCOLOR": {"xh2": 1715, "xh2s": 1714, "xt5": None},
    "UI_SETP_PERFORMANCE": {"xh2": None, "xh2s": None, "xt5": None},
    "UI_SETP_GRAIN": {"xh2": 262, "xh2s": None, "xt5": None},
}
print("\n== известные нам ID против каталога fujimod ==")
ids = {}
for cam, key in (("xh2/5.30", "xh2"), ("xh2s/7.30", "xh2s"), ("xt5/4.31", "xt5")):
    p = os.path.join(CAT, cam.replace("/", "\\"), "ui-setting-names.generated.json")
    j = json.load(open(p, encoding="utf-8"))["ui_setting_names"]
    ids[key] = j
    print(" %-6s всего=%d  UI_SETP_NONE=%s  UI_SETP_MAX=%s" % (key, len(j), j.get("UI_SETP_NONE"), j.get("UI_SETP_MAX")))
    for name, per in KNOWN.items():
        if name in j:
            print("    %-26s fujimod=%-6s наше=%s" % (name, j[name], per.get(key)))
# перекрёстная проверка одинаковых имён между моделями
names = set(ids["xh2"]) | set(ids["xh2s"]) | set(ids["xt5"])
diff = [n for n in names if len({ids[k].get(n) for k in ids if n in ids[k]}) > 1]
print("\nимён, у которых ID различается между моделями: %d (примеры: %s)" % (len(diff), diff[:8]))
for n in ("UI_SETP_FILM_SIM", "UI_SETP_STILLCOLOR", "UI_SETP_BRACKET", "UI_SETP_ISO_BKT",
          "UI_SETP_DRIVE_MODE", "UI_SETP_MULTI_EXPO", "UI_SETP_HDR", "UI_SETP_MODE_RECORD"):
    print("  %-26s xh2=%-6s xh2s=%-6s xt5=%-6s" % (n, ids["xh2"].get(n), ids["xh2s"].get(n), ids["xt5"].get(n)))

json.dump(report, open(os.path.join(HERE, "s3_сверка_имён.json"), "w", encoding="utf-8"),
          ensure_ascii=False, indent=2)
