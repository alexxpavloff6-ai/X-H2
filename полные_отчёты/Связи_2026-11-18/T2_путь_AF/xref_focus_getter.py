"""Read-only cross-reference scan for selected X-H2 5.30 AF property ids."""
import json
import re
import struct
import sys
from pathlib import Path

FW_DIR = Path(r"<корень проекта>\Анализ_прошивки\Сравнение_версий_2026-11-16")
sys.path.insert(0, str(FW_DIR))
from fwcommon import load, cs, func_start  # noqa: E402

GETTER = 0x2C93FD4
IDS = {
    0x8C0, 0x6FB, 0x620, 0x618, 0x61C, 0x70D,
    *range(0x710, 0x724), 0x1E2, *range(0x5BA, 0x5BF),
}


def bl_target(word, pc):
    if word >> 26 != 0b100101:
        return None
    imm = word & 0x03FFFFFF
    if imm & (1 << 25):
        imm -= 1 << 26
    return pc + imm * 4


def main():
    block = load("X-H2", "old", 1)
    found = []
    for off in range(0, len(block.data) - 3, 4):
        word = struct.unpack_from("<I", block.data, off)[0]
        va = block.base + off
        if bl_target(word, va) != GETTER:
            continue
        lo = max(0, off - 20)
        prev = list(cs.disasm(block.data[lo:off], block.base + lo))
        prop_id = None
        for insn in reversed(prev):
            match = re.search(r"w0, #(0x[0-9a-f]+|[0-9]+)", insn.op_str)
            if insn.mnemonic.startswith("mov") and match:
                candidate = int(match.group(1), 0)
                if candidate in IDS:
                    prop_id = candidate
                break
        if prop_id is None:
            continue
        start = func_start(block, va)
        found.append({"id": hex(prop_id), "call": hex(va), "function": hex(start) if start else None})
    print(json.dumps({"getter": hex(GETTER), "block": 1, "calls": found}, ensure_ascii=False, indent=2))


if __name__ == "__main__":
    main()
