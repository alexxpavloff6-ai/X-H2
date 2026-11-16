# -*- coding: utf-8 -*-
"""Проверка: совпадает ли порядок ID из fujimod с порядком строк в наших блоках.

Если таблица «ID -> строка» лежит в .rodata блока 0 и строки идут в порядке ID,
то адреса наших строк, отсортированные по ID fujimod, должны возрастать.
Дополнительно: откуда взялись имена, которых у fujimod нет (блок 0 или 1),
и есть ли пропуски в нумерации ID."""
import json, os, re, sys
sys.stdout.reconfigure(encoding="utf-8")

CAT = r"<корень проекта>\Внешние_репозитории\fujimod\catalog\firmware"
OURS = r"<корень проекта>\Анализ_прошивки\Сравнение_версий_2026-11-16\F_режим_съёмки\strings"

CASES = [("XH2_5.30", "xh2/5.30"), ("XH2S_7.30", "xh2s/7.30"), ("XT5_4.31", "xt5/4.31")]
RX = re.compile(r"^(UI_SETP_[A-Za-z0-9_]+|UILIB_[A-Za-z0-9_]+)$")

for prefix, cam in CASES:
    print("=" * 70)
    print(prefix)
    fj = json.load(open(os.path.join(CAT, cam.replace("/", "\\"), "ui-setting-names.generated.json"),
                        encoding="utf-8"))["ui_setting_names"]
    ids = sorted(fj.values())
    missing = sorted(set(range(max(ids) + 1)) - set(ids))
    dup = len(fj) - len(set(fj.values()))
    print("  имён=%d  ID 0..%d  пропусков=%d %s  повторов ID=%d" % (
        len(fj), max(ids), len(missing), missing[:10], dup))

    # наши адреса по блокам
    addr = {}
    blk = {}
    for b in ("b0", "b1"):
        p = os.path.join(OURS, "%s_%s.txt" % (prefix, b))
        for line in open(p, encoding="utf-8", errors="replace"):
            line = line.rstrip("\n")
            if "\t" not in line:
                continue
            a, s = line.split("\t", 1)
            if RX.match(s) and s.startswith("UI_SETP_"):
                addr.setdefault(s, int(a, 16))
                blk.setdefault(s, b)

    common = [n for n in fj if n in addr]
    seq = sorted(common, key=lambda n: fj[n])
    addrs = [addr[n] for n in seq]
    increases = sum(1 for i in range(1, len(addrs)) if addrs[i] >= addrs[i - 1])
    print("  общих=%d; монотонность адресов по ID: %d/%d (%.1f%%)" % (
        len(seq), increases, len(addrs) - 1, 100.0 * increases / max(1, len(addrs) - 1)))
    # грубые нарушения
    bad = [(seq[i], fj[seq[i]], hex(addrs[i]), hex(addrs[i - 1]), seq[i - 1]) for i in range(1, len(addrs)) if addrs[i] < addrs[i - 1]]
    print("  нарушений: %d; первые 5:" % len(bad))
    for x in bad[:5]:
        print("   ", x)

    extras = sorted(set(addr) - set(fj))
    print("  имён сверх fujimod: %d (блок0=%d, блок1=%d)" % (
        len(extras), sum(1 for n in extras if blk[n] == "b0"), sum(1 for n in extras if blk[n] == "b1")))
    print("  примеры сверх fujimod:", extras[:10])

    # сцены
    fjs = json.load(open(os.path.join(CAT, cam.replace("/", "\\"), "ui-scene-names.generated.json"),
                         encoding="utf-8"))["ui_scene_names"]
    saddr, sblk = {}, {}
    for b in ("b0", "b1"):
        p = os.path.join(OURS, "%s_%s.txt" % (prefix, b))
        for line in open(p, encoding="utf-8", errors="replace"):
            line = line.rstrip("\n")
            if "\t" not in line:
                continue
            a, s = line.split("\t", 1)
            if RX.match(s) and s.startswith("UILIB_"):
                saddr.setdefault(s, int(a, 16))
                sblk.setdefault(s, b)
    ids = sorted(fjs.values())
    miss = sorted(set(range(max(ids) + 1)) - set(ids))
    common = [n for n in fjs if n in saddr]
    seq = sorted(common, key=lambda n: fjs[n])
    a2 = [saddr[n] for n in seq]
    inc = sum(1 for i in range(1, len(a2)) if a2[i] >= a2[i - 1])
    ex = sorted(set(saddr) - set(fjs))
    print("  СЦЕНЫ: имён=%d ID 0..%d пропусков=%d; монотонность %d/%d (%.1f%%); сверх fujimod=%d (b0=%d,b1=%d)" % (
        len(fjs), max(ids), len(miss), inc, len(a2) - 1, 100.0 * inc / max(1, len(a2) - 1),
        len(ex), sum(1 for n in ex if sblk[n] == "b0"), sum(1 for n in ex if sblk[n] == "b1")))
    print("  примеры сцен сверх fujimod:", ex[:8])
