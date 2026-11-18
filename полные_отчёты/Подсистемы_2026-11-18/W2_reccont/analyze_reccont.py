from __future__ import annotations
import json
import re
import sys
from pathlib import Path

HERE = Path(__file__).resolve().parent
PROJECT = HERE.parents[2]
ANALYSIS = PROJECT / "Анализ_прошивки"
FW_DIR = ANALYSIS / "Сравнение_версий_2026-11-16"
sys.path.insert(0, str(FW_DIR))
from fwcommon import load, insns, bl_callers  # noqa: E402

SOURCE = ANALYSIS / "Записи_2026-11-18" / "U2_каталог_записей" / "registered_records.json"
record_index = json.loads(SOURCE.read_text(encoding="utf-8"))
rec = next(r for r in record_index["records"] if int(r["id"], 16) == 3)

KNOWN_EVENTS = set(range(0x200, 0x22F)) | set(range(0x1212, 0x1215)) | {0x1220, 0x1221, 0x1222}

def event_code(block, function, site):
    b = load("X-H2", "old", block)
    start, end = int(function, 16), int(site, 16)
    candidates = []
    for i in insns(b, start, max(1, (end - start) // 4 + 1)):
        if i.address >= end:
            break
        if i.mnemonic in ("mov", "movz") and i.op_str.startswith("w0, #"):
            try:
                value = int(i.op_str.split("#", 1)[1], 0)
            except ValueError:
                continue
            if value in KNOWN_EVENTS:
                candidates.append(value)
    return f"0x{candidates[-1]:04X}" if candidates else None

writers = []
for w in rec["writers"]:
    code = event_code(w["block"], w["function"], w["site"])
    writers.append({
        "block": w["block"], "site": w["site"], "function": w["function"],
        "event": code,
        "event_source": "constant in publisher" if code else "generic publisher; code comes from argument or indirect context",
    })

by_event = {}
for w in writers:
    if w["event"]:
        by_event.setdefault(w["event"], []).append(w)

# Independent counts from direct references to record API in the selected firmware.
result = {
    "project": "Fujifilm X-H2 firmware 5.30",
    "scope": "static, read-only analysis; no camera access",
    "record": {
        "id": "0x03", "element_count": 48, "element_size": "0x50", "max_payload": "0x48",
        "registration_function": "0x2D5A998", "registration_site": "0x2D5A9DC",
        "reader_loop": "0x2D67134", "publisher_api": "0x14CF124", "reader_api": "0x14CF354",
    },
    "cycle": {
        "queue_get": "0x14CF354(id=3, output=global 0x3BC2B48, index=-1)",
        "on_nonzero_return": ["0x2D5B36C", "retry get"],
        "on_success": ["copy header pair", "0x2E00D18 state gate", "if gate != 1 copy payload", "0x2D9A060", "0x2D5B36C", "retry get"],
        "exit": "visible path returns 1 at 0x2D671BC; start/stop callbacks continue to separate handlers",
    },
    "event_counts": {"block_0_record3_writers": 4, "block_1_record3_writers": 43, "recorded_writers": len(writers)},
    "event_publishers": writers,
    "event_groups": {k: v for k, v in sorted(by_event.items())},
    "event_payload_sizes_confirmed": {
        "0x0200": "0x28", "0x0204": "0x0C", "0x0205": "0x04", "0x0206": "0x2C",
        "0x1212": "0", "0x1213": "0", "0x1214": "0",
        "0x1220": "0x10", "0x1221": "0x10", "0x1222": "0x10",
    },
    "handler_effects": {
        "0x2D9A060": "for event IDs 0x1228/0x1229, sets message +0x18 to 0/1/2/3 based on bits 0..2 of a global mask; other IDs return without this adjustment",
        "0x2D5B290": "maps event 0x0200 (condition on global +0x1FC) to state +0xFC0 = 0 or 1; 0x1221->2, 0x1220->3, 0x1222->4, others->5; calls 0x2D5AD60(4)",
        "0x2D5B398": "for selected events 0x0200,0x0201,0x020B,0x0203..0x0209,0x0214,0x021F,0x0226,0x022A,0x022B,0x022D,0x1130 it updates state +0xFC2 and calls 0x2D5AD60(5); conditions include event payload/global values",
        "0x2E00D18": "reads scalar state via 0x14CF404 and gates handling through 0x2E2704C/0x2E20AD8/0x2E24520; not a named exposure or file writer",
    },
    "settings_boundary": {
        "MODE_RECORD_resolver": "0x1141EE0 in block 0; enum evidence includes P/S/A/M 0x21..0x24 and HDR 0x2C",
        "record_context": "[ctx+0x3978] belongs to RECF frame-processing context; direct reads/writes are in frame preparation, not proven in reccont event handlers",
        "reccont_direct_settings_reads": "none established for UI_SETP_CONTINUOUS 0x858, DOTLCD_CONTINUOUS 0xACE/0xACF, shutter UI_SETP 0x827 or exposure output; context reads by separate RECIF/RECF path are not a reccont link",
        "shutter_structure": "the shooting structure is documented at [*0x3BCAB48 + 0x3478]; +0x19AC is actual shutter and +0x1994 actual shutter speed; no direct read from reccont loop/handlers established",
    },
    "confidence": {
        "D": ["queue registration/size, publisher and reader counts, direct event IDs and payload lengths where listed, loop control flow, state writes in handlers"],
        "K": ["record 0x03 is a capture-control event channel based on reccont label, event families and handler state changes"],
        "G_or_open": ["mapping event IDs to shutter press, exposure start/end, frame completion, burst, HDR/bracketing or movie semantics; connection to JPEG/RAW writers, MOVDC or filesystem"],
    },
    "limitations": ["static instructions do not identify all indirect calls or runtime sender order", "no evidence that event IDs alone encode the full lifecycle", "do not equate mode code 0x2C/HDR with the record event code 0x020C or infer bracketing/video from numeric proximity"],
}
(HERE / "результат.json").write_text(json.dumps(result, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")
print(f"wrote {HERE / 'результат.json'}; writers={len(writers)}; event_ids={len(by_event)}; block0={sum(w['block']==0 for w in writers)}; block1={sum(w['block']==1 for w in writers)}")

