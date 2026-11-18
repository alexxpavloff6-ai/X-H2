from __future__ import annotations

import json
import struct
import sys
from pathlib import Path

ANALYSIS = Path(r"<корень проекта>\Анализ_прошивки")
sys.path.insert(0, str(ANALYSIS / "Сравнение_версий_2026-11-16"))
from fwcommon import load, dis, adrp_refs, find_bytes  # noqa: E402


def main() -> None:
    for idx in (0, 1, 2):
        b = load("X-H2", "old", idx)
        print("\nBLOCK", idx, b)
        for va in (0x32AEDD0, 0x3443000, 0x3443590, 0x18CAA94, 0x1654ED0, 0x16682E8):
            if b.base <= va < b.end:
                off = va - b.base
                print(f"\nDATA {va:#x} offset={off:#x}")
                for i in range(0, 0x100, 16):
                    chunk = b.data[off + i:off + i + 16]
                    print(f"{va+i:08x}: {chunk.hex(' ')}")
        for t in (0x32AEDD0, 0x3443000, 0x3443590, 0x18CAA94, 0x1654ED0, 0x16682E8):
            rr = adrp_refs(b, t)
            if rr:
                print("REFS", hex(t), rr[:30])
        if idx == 1:
            print("\nDIS 0x2bf2ec0\n", dis(b, 0x2bf2ec0, 80))
            print("\nDIS registry ref funcs")
            for site in [x["site"] for x in adrp_refs(b, 0x3443000) + adrp_refs(b, 0x3443590)]:
                print(hex(site), dis(b, site - 12, 35))
            for code in (0xD18C, 0xD18D, 0xD18E, 0xD197, 0xD1A5):
                needle = code.to_bytes(4, "little")
                hits = find_bytes(b, needle)
                print("WORD", hex(code), [hex(x) for x in hits[:80]], "count", len(hits))
                needle2 = code.to_bytes(2, "little")
                hits2 = find_bytes(b, needle2)
                print("HALF", hex(code), [hex(x) for x in hits2[:80]], "count", len(hits2))


if __name__ == "__main__":
    main()
