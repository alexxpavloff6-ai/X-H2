# -*- coding: utf-8 -*-
"""Сравнение наборов имён UI_SETP между X-H2/X-H2S/X-T5 + покрытие XP5-камер в firmware-versions
+ содержимое recovery/green-led для xp5."""
import json, os, sys
sys.stdout.reconfigure(encoding="utf-8")

CAT = r"<корень проекта>\Внешние_репозитории\fujimod\catalog"
sets = {}
for cam, ver in (("xh2", "5.30"), ("xh2s", "7.30"), ("xt5", "4.31")):
    j = json.load(open(os.path.join(CAT, "firmware", cam, ver, "ui-setting-names.generated.json"), encoding="utf-8"))
    sets[cam] = set(j["ui_setting_names"])

print("== имена настроек: только в одной из трёх камер ==")
allnames = set().union(*sets.values())
for cam in ("xh2", "xh2s", "xt5"):
    only = sorted(n for n in sets[cam] if not any(n in sets[o] for o in sets if o != cam))
    print("  только %-5s (%d): %s" % (cam, len(only), only[:14]))
for a, b in (("xh2", "xh2s"), ("xh2", "xt5"), ("xh2s", "xt5")):
    print("  %-5s \\ %-5s: %d   %-5s \\ %-5s: %d" % (a, b, len(sets[a] - sets[b]), b, a, len(sets[b] - sets[a])))
diff_all = sorted(allnames - sets["xh2"] - sets["xh2s"] - sets["xt5"])
print("  ни в одной: %d" % len(diff_all))

print("\n== firmware-versions: все XP5-камеры ==")
fv = json.load(open(os.path.join(CAT, "firmware-versions.generated.json"), encoding="utf-8"))["releases"]
xp5_bodies = ("xh2", "xh2s", "xt5", "xs20", "xt50", "xm5", "x100vi", "xe5", "xt30iii", "xhalf")
for r in fv:
    if r["firmware_id"].split("-")[0] in xp5_bodies:
        print("  %-10s %-6s internal=%-8s %s" % (r["product"], r["version"], r["internal_version"], r["update_sha256"][:16]))
print("  всего релизов: %d; версий 5.33/7.31/4.32: %s" % (
    len(fv), [r["version"] for r in fv if r["version"] in ("5.33", "7.31", "4.32")]))

print("\n== recovery/green-led: запись xp5 ==")
gl = json.load(open(os.path.join(CAT, "recovery", "green-led.generated.json"), encoding="utf-8"))
for item in gl:
    s = json.dumps(item, ensure_ascii=False)
    if "xp5" in s.lower():
        print(json.dumps(item, ensure_ascii=False, indent=1)[:1800])
        break
print("\n== recovery/recipes: ключи/ids ==")
rc = json.load(open(os.path.join(CAT, "recovery", "recipes.generated.json"), encoding="utf-8"))
print("  тип:", type(rc).__name__, "| размер:", len(rc))
sample = rc if isinstance(rc, list) else list(rc.items())
for x in sample[:3]:
    print("  ", json.dumps(x, ensure_ascii=False)[:300])
s = json.dumps(rc, ensure_ascii=False)
for k in ("xp5", "xh2", "X-H2", "X-H2S", "X-T5"):
    print("  %-6s в recipes: %s" % (k, k in s))
