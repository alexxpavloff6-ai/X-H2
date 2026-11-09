"""Read-only inspection of the supplied Fujifilm X-H2 firmware.

The FFLZ decoding rules follow tiredboffin/fffw (MIT):
https://github.com/tiredboffin/fffw/blob/main/ffcompress/fflz/decompressor.go
The accompanying MIT notice is in инструменты/Лицензия_fffw.txt.
No connection to a camera, firmware modification or repacking is performed.
"""
from pathlib import Path
import hashlib
import json
import re
import struct
import sys

OUT = Path(__file__).resolve().parent
SOURCE = OUT.parent / "FIRMWARE" / "ver 5.30" / "FWUP0028.DAT"
sys.path.insert(0, str(OUT / "инструменты"))

from capstone import Cs, CS_ARCH_ARM64, CS_MODE_LITTLE_ENDIAN, __version__ as capstone_version
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec, utils

EXPECTED_SHA256 = "be47168cb075ef726e67cb4bb08175a896047a3b0de2bcb6e65333b22cfcb203"
TRANSLATION = bytes.maketrans(bytes(range(256)), bytes(255-i for i in range(256)))
ASCII = re.compile(rb"[\x20-\x7e]{8,}")
CATEGORIES = {
    "автофокус": re.compile(rb"(?:AFCCUS|AFC_CUSTOM|AFSPEED|AF_SPEED|FACEDETECT|FACE_DETECT|EYEAF|EYE_DETECT|DETECT_SUBJ|FOCUS_|AFCHASE|AF_CTRL|AF_CTRL|afCtrl)", re.I),
    "меню_управление": re.compile(rb"(?:UI_MENUCOM_ITEM|UI_Q_MENU|UI_MYMENU|UI_FUNC_SET|KEY_FOCUS|MENU_MYMENU|MENU_CUSTOM|FUNCTIONBUTTON|KEY_FACE)", re.I),
    "имитации_пленки": re.compile(rb"(?:MODE_FSIM_|UI_FILM_SIM_|UI_SETP_FILM_SIM|UI_MENUCOM_ITEM_FILM_SIM|UI_Q_MENU_FILM_SIM|UI_MYMENU_FILM_SIM|UI_FUNC_SET_FSIM|REALA|PROVIA|VELVIA|ASTIA|CLASSIC_CHROME|ETERNA|NOSTALG|ACROS)", re.I),
    "система_язык": re.compile(rb"(?:COMPILER=|GCC:|GNU C|ThreadX|Linux version|[A-Za-z0-9_/\\.-]+\.(?:c|cpp|cc)\b|__cxa_|^_ZN)")
}

def sha256(data):
    return hashlib.sha256(data).hexdigest()

def unpack_fflz(data, off):
    usize, csize, pages, page_size, alignment = struct.unpack_from("<5I", data, off)
    packed = memoryview(data)[off:off+csize]
    pos, result = 20, bytearray()
    while pos < csize:
        token = packed[pos]
        pos += 1
        if token < 128:
            if pos + token > csize:
                raise ValueError("FFLZ literal exceeds input")
            result.extend(packed[pos:pos+token])
            pos += token
        else:
            if pos >= csize:
                raise ValueError("FFLZ match exceeds input")
            second = packed[pos]
            pos += 1
            length = second & 15
            distance = ((token & 127) << 4) | (second >> 4)
            if not 0 < length <= distance <= len(result):
                raise ValueError("Invalid FFLZ back reference")
            start = len(result) - distance
            result.extend(result[start:start+length])
        if len(result) > usize:
            raise ValueError("FFLZ output exceeds declared size")
    short = usize-len(result)
    if 0 < short <= 127 and csize % 16384 == 0:
        result.extend(bytes(short))
    if len(result) != usize:
        raise ValueError("FFLZ decoded size mismatch")
    return bytes(result)

def main():
    raw = SOURCE.read_bytes()
    original_hash = sha256(raw)
    if original_hash != EXPECTED_SHA256:
        raise ValueError("Unexpected input hash; investigate before reusing this analysis")
    decoded = raw.translate(TRANSLATION)
    major, minor = struct.unpack_from("<2I", raw, 0x204)
    signature = raw[-72:]
    r, s = utils.decode_dss_signature(signature)
    key_path = OUT / "инструменты" / "xh2_pubkey.pem"
    public_key = serialization.load_pem_public_key(key_path.read_bytes())
    public_key.verify(signature, raw[:-72], ec.ECDSA(hashes.SHA256()))
    public_point = public_key.public_bytes(serialization.Encoding.X962, serialization.PublicFormat.UncompressedPoint)
    result = {
        "source": str(SOURCE),
        "size_bytes": len(raw),
        "size_MiB": len(raw)/2**20,
        "sha256": original_hash,
        "header": {
            "format_field_u32_at_0": struct.unpack_from("<I", raw)[0],
            "version": f"{major:x}.{minor:02x}",
            "model_strings_file_offsets": [hex(m.start()) for m in re.finditer(rb"X-H2\x00", decoded)],
        },
        "transformation": "byte XOR 0xff; original retained",
        "signature": {
            "algorithm": "ECDSA", "curve": public_key.curve.name, "digest": "SHA-256",
            "offset": len(raw)-72, "length": 72,
            "covered_start": 0, "covered_length": len(raw)-72, "verified": True,
            "r_bits": r.bit_length(), "s_bits": s.bit_length(),
            "public_key_source": "https://github.com/tiredboffin/fffw/blob/main/ffun/ports/xh2/pubkey.pem",
            "public_key_blob_sha": "de2acfd797e1c70e32e0e48eecf27931b93e07e6",
            "public_key_point_file_offset_after_inversion": decoded.find(public_point),
        },
        "fflz_blocks": [],
        "string_match_counts": {},
        "source_line_count": None,
        "source_line_count_reason": "Compiled firmware image; original source files are absent",
        "capstone_version": capstone_version,
    }
    records = []
    def collect(data, region):
        counts = {}
        for name, pattern in CATEGORIES.items():
            chosen = [m for m in ASCII.finditer(data) if pattern.search(m.group())]
            counts[name] = len(chosen)
            for m in chosen:
                records.append((region, hex(m.start()), name, m.group().decode("ascii").replace("\t", "\\t")))
        result["string_match_counts"][region] = counts

    collect(decoded[0x214:], "побитово_преобразованный_образ_от_0x214")
    for match in re.finditer(re.escape(bytes.fromhex("0040000004000000")), decoded):
        off = match.start()-12
        if off < 0:
            continue
        u, c, n, pg, align = struct.unpack_from("<5I", decoded, off)
        if not (20 < c < u < 256*2**20 and (c+16383)//16384 == n and off+c <= len(decoded)-72):
            continue
        content = unpack_fflz(decoded, off)
        result["fflz_blocks"].append({
            "file_offset": hex(off), "packed_size_including_header": c, "unpacked_size": u,
            "pages": n, "page_size": pg, "alignment": align,
            "decoded_sha256": sha256(content), "size_verified": True,
        })
        collect(content, "распакованный_блок_" + hex(off))
    result["total_fflz_unpacked_bytes"] = sum(x["unpacked_size"] for x in result["fflz_blocks"])
    elf_off = decoded.find(b"\x7fELF")
    result["embedded_elf"] = {
        "file_offset": hex(elf_off), "class": decoded[elf_off+4],
        "data_encoding": decoded[elf_off+5],
        "machine": struct.unpack_from("<H", decoded, elf_off+18)[0],
    }
    dtb_off = decoded.find(bytes.fromhex("d00dfeed"))
    result["device_tree"] = {
        "file_offset": hex(dtb_off), "size": struct.unpack_from(">I", decoded, dtb_off+4)[0],
        "cortex_a53_string_offsets": [hex(m.start()) for m in re.finditer(b"arm,cortex-a53", decoded)]
    }
    # Extract selected UTF-16LE strings from the resource area. These are resources,
    # not source lines or function counts.
    area_start, area_end = 0x2a00000, 0x3700000
    text_area = decoded[area_start:area_end].decode("utf-16-le", errors="replace")
    menu_pattern = re.compile(r"[\x20-\x7e\u0400-\u04ff]{4,}")
    menu_words = re.compile(r"AF-C|AF-S|MY MENU|SHOOTING MENU|FILM SIM|REALA|PROVIA|VELVIA|ASTIA|CLASSIC|ETERNA|ACROS|NOSTALG|АВТОФОКУС|ИМИТАЦ|МОДЕЛИРОВ|ПЛ[ЕЁ]НК|БАЛАНС БЕЛОГО|РЕЗКОСТ", re.I)
    menu = [(hex(area_start+m.start()*2), m.group().replace("\t", "\\t")) for m in menu_pattern.finditer(text_area) if menu_words.search(m.group())]
    result["selected_utf16_resource_strings"] = len(menu)
    assembly = [
        "; Реальные команды ARM64 после побитового преобразования исходного образа.",
        "; Адреса в первом столбце – смещения в DAT, а не адреса оперативной памяти.",
        "; Назначение функции не установлено; этот фрагмент не назван кодом автофокуса.",
    ]
    engine = Cs(CS_ARCH_ARM64, CS_MODE_LITTLE_ENDIAN)
    for address, size, mnemonic, operands in engine.disasm_lite(decoded[0xad0:0xaf4], 0xad0):
        assembly.append(f"{address:08X}  {decoded[address:address+size].hex(' '):12}  {mnemonic:8} {operands}")
    (OUT / "машинные_команды.asm").write_text("\n".join(assembly)+"\n", encoding="utf-8")
    (OUT / "найденные_обозначения.tsv").write_text(
        "область\tсмещение_внутри_области\tкатегория\tстрока\n"
        + "\n".join("\t".join(row) for row in records)+"\n", encoding="utf-8-sig")
    (OUT / "тексты_меню.tsv").write_text(
        "смещение_в_файле\tтекст\n" + "\n".join("\t".join(row) for row in menu)+"\n", encoding="utf-8-sig")
    result["input_unchanged"] = sha256(SOURCE.read_bytes()) == original_hash
    if not result["input_unchanged"]:
        raise ValueError("Input hash changed during analysis")
    (OUT / "сведения.json").write_text(json.dumps(result, ensure_ascii=False, indent=2)+"\n", encoding="utf-8")
    print(json.dumps({
        "version": result["header"]["version"], "sha256": original_hash,
        "signature_verified": result["signature"]["verified"],
        "blocks": len(result["fflz_blocks"]), "unpacked_bytes": result["total_fflz_unpacked_bytes"],
        "selected_identifiers": len(records), "selected_menu_strings": len(menu),
        "input_unchanged": result["input_unchanged"],
    }, ensure_ascii=True, indent=2))

if __name__ == "__main__":
    main()
