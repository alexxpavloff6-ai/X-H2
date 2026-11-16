# -*- coding: utf-8 -*-
"""Проверка сигнатур XP5-flash-локатора fujimod (crates/corpus/src/locators/flash.rs:255-333)
на наших DAT: X-H2S 7.30 (блок 0) и X-T5 4.31 (блок 0).

Локатор ищет:
  * flash_read: str x0,[sp,#0x10]; str x1,[sp,#0x18]; str w2,[sp,#0x20]; str w3,[sp,#0x24]; ret
  * flash_window_address: 3 инструкции mov x1,#0xf0000000; add x0,x0,x1; ret
  * read request: mov x0,#0xf8000000; mov w0,#0x7ffffff; movk w0,#0x7766,lsl#16; mov w0,#0x6555
  * dispatcher: tst x0,#0x3f
Плюс печатает диапазоны кода из flash.generated.json."""
import struct, sys
sys.path.insert(0, r"<корень проекта>\Анализ_прошивки\Сравнение_версий_2026-11-16")
sys.stdout.reconfigure(encoding="utf-8")
from fwcommon import load, dis, insns, Block

CASES = [
    ("X-H2S", "old", 0, {"flash_read": 0x16A4B50, "request": 0x16A48A4,
                         "dispatcher": 0x16A41BC, "dma": 0x16A383C, "cache": 0x17F1674,
                         "bank": 0x16A5388, "tail": 0x16A3A7C}),
    ("X-T5", "old", 0, {"flash_read": 0x1384FE8, "request": 0x1384D3C,
                        "dispatcher": 0x1384654, "dma": 0x1383CC8, "cache": 0x14C99D8,
                        "bank": 0x1385848, "tail": 0x1383F08}),
]

for model, state, idx, addrs in CASES:
    b = load(model, state, idx)
    print("=" * 74)
    print(model, b.version, "блок", idx, hex(b.base), "размер", hex(len(b.data)))

    for name, va in addrs.items():
        n = 12 if name in ("flash_read", "cache") else 16
        print("\n-- %s @0x%X --" % (name, va))
        print(dis(b, va, n))

    # сигнатура flash_read по инструкциям
    expect = [("str", "x0, [sp, #0x10]"), ("str", "x1, [sp, #0x18]"),
              ("str", "w2, [sp, #0x20]"), ("str", "w3, [sp, #0x24]"), ("ret", "")]
    got = [(i.mnemonic, i.op_str) for i in insns(b, addrs["flash_read"], 5)]
    print("\nflash_read сигнатура совпала: %s" % (got == expect))
    if got != expect:
        print("  ожидалось", expect)
        print("  получено ", got)

    # поиск 3-инструкционной window-функции: mov x1,#0xf0000000 ; add x0,x0,x1 ; ret
    hits = []
    data, base = b.data, b.base
    for o in range(0, len(data) - 12, 4):
        w = struct.unpack_from("<I", data, o)[0]
        if (w & 0xFFE0001F) != 0xD2A00001:
            continue
        if ((w >> 5) & 0xFFFF) != 0xF000 or ((w >> 21) & 3) != 1:  # hw == 1 -> <<16
            continue
        ins = list(insns(b, base + o, 3))
        if len(ins) == 3 and ins[0].mnemonic == "mov" and ins[0].op_str == "x1, #0xf0000000" \
                and ins[1].mnemonic == "add" and ins[1].op_str == "x0, x0, x1" \
                and ins[2].mnemonic == "ret":
            hits.append(base + o)
    print("window-функция 'mov x1,#0xf0000000; add x0,x0,x1; ret' найдена по адресам:", [hex(x) for x in hits])

    # маркеры в read request
    req = dis(b, addrs["request"], 172)  # 684/4 = 171 инструкция
    for marker in ("#0xf8000000", "#0x7ffffff", "#0x7766", "#0x6555", "#0x3f"):
        print("  маркер %-12s в request: %s" % (marker, marker in req))
    disp = dis(b, addrs["dispatcher"], 78)
    print("  tst x0, #0x3f в dispatcher:", "tst x0, #0x3f" in disp)
