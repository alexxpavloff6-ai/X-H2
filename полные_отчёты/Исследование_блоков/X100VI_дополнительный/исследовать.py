"""X100VI FFLZ: только чтение DAT; смещения не смешиваются. FFLZ: fffw MIT,
см. ../../инструменты/Лицензия_fffw.txt. Запуск: python исследовать.py.
Нужен Python 3 и локальный capstone из Анализ_прошивки/инструменты.
"""
from pathlib import Path
import hashlib, importlib.util, json, re, struct, sys

HERE = Path(__file__).resolve().parent
AN = HERE.parent.parent
ROOT = AN.parent
sys.path.insert(0, str(AN / 'инструменты'))
spec = importlib.util.spec_from_file_location('base', AN / 'анализ_файла.py')
base = importlib.util.module_from_spec(spec)
spec.loader.exec_module(base)
from capstone import Cs, CS_ARCH_ARM64, CS_MODE_ARM

H = lambda x: hashlib.sha256(x).hexdigest()
src = ROOT / 'Firmware на прочиеFuji' / 'FPUPDATE.DAT'
raw = src.read_bytes()
initial = H(raw)
if initial != '0d48d2ae26ac7ebab9b0e4cac56324807ec1ea8ae30df06b0b9e79066dc0a14a':
    raise ValueError('Неверная версия исходного DAT')
data = raw.translate(base.TRANSLATION)
off = 0x1402bc
unpacked, packed, pages, page, alignment = struct.unpack_from('<5I', data, off)
b = base.unpack_fflz(data, off)
assert len(b) == unpacked
u64 = struct.unpack_from('<8Q', b)
strings = [b'recovery_main', b'recovery_disp', b'recovery_update', b'recovery_key', b'RKEY ERR', b'updatedata', b'A:\\FPUPDATE.DAT', b' deflate 1.2.11', b' inflate 1.2.11', b'FUJIFILM', b'Exif', b'\x7fELF', b'\xd0\x0d\xfe\xed', b'ARM\x64']
def occurrences(haystack, needle, limit=100):
    positions = []
    pos = 0
    while len(positions) < limit:
        pos = haystack.find(needle, pos)
        if pos < 0: break
        positions.append(hex(pos)); pos += 1
    return positions
md = Cs(CS_ARCH_ARM64, CS_MODE_ARM)
md.detail = True
# Выбранные адресные пары ADRP+ADD, сканирование первой части кода.
targets = {b.find(s): s.decode('ascii') for s in strings[:7]}
refs = []
instructions = list(md.disasm(b[0x40:0x83000], 0x40))
for j, ins in enumerate(instructions):
    if ins.mnemonic != 'adrp' or len(ins.operands) != 2: continue
    reg, pg = ins.operands[0].reg, ins.operands[1].imm
    for nxt in instructions[j+1:j+6]:
        if nxt.address > ins.address + 20: break
        if nxt.mnemonic == 'add' and len(nxt.operands) == 3 and nxt.operands[1].reg == reg and nxt.operands[2].type == 2:
            dest = pg + nxt.operands[2].imm
            if dest in targets:
                refs.append({'adrp': hex(ins.address), 'add': hex(nxt.address), 'target': hex(dest), 'text': targets[dest]})
# Ограниченная выборка точного байтового совпадения: не утверждение о полном отсутствии общего кода.
other_offsets = [0x4402bc, 0x9c02bc, 0x10e02bc, 0x1a202bc, 0x2b602bc]
windows = [0x40, 0x4c, 0x184, 0x410, 0x4f8, 0x60c, 0x1dbc, 0x1e88, 0x2914, 0x2a58, 0x37c8, 0x14dd38]
comparisons = []
for o in other_offsets:
    other = base.unpack_fflz(data, o)
    hits = {hex(w): occurrences(other, b[w:w+64], 10) for w in windows}
    names = {s.decode(): occurrences(other, s, 10) for s in strings[:5]}
    comparisons.append({'dat_offset': hex(o), 'size': len(other), 'sha256': H(other), 'first32': other[:32].hex(), 'exact_64_byte_windows': hits, 'recovery_name_occurrences': names})
# Только буквальные LE значения в инвертированном DAT; ссылки могут кодироваться иначе.
values = [off, 0x881000, 0x88104c, 0x1ff000]
needles = {hex(v): {'u32le': occurrences(data, struct.pack('<I',v)), 'u64le': occurrences(data, struct.pack('<Q',v))} for v in values}
lines = ['; AArch64, все адреса — смещения относительно распакованного FFLZ, не адреса DAT/RAM.', '; Условные ветви не доказывают реального запуска; базовый адрес не установлен.']
ranges = [(0x40,0xd8),(0x184,0x1a0),(0x3f0,0x498),(0x4f8,0x518),(0x60c,0x6d0),(0x1304,0x13a4),(0x159c,0x1bc4),(0x1e88,0x1f0c),(0x28b4,0x28d4),(0x2a58,0x2ad4),(0x37c8,0x38b0),(0x7d1d8,0x7d1ec),(0x7d2fc,0x7d310),(0x80fb4,0x81024),(0x82a64,0x82b40),(0x98778,0x987e4)]
for a,z in ranges:
    lines.append('\n; диапазон '+hex(a)+'..'+hex(z)+' (конец исключён)')
    for i in md.disasm(b[a:z],a):
        lines.append(f'{i.address:08x}  {i.bytes.hex(" "):11}  {i.mnemonic:8} {i.op_str}')
(HERE / 'фрагменты.asm').write_text('\n'.join(lines)+'\n',encoding='utf-8')
result = {'source':str(src.relative_to(ROOT)), 'source_sha256':initial,'transformation':'XOR FF, in memory', 'dat_offset':hex(off), 'fflz_header_raw_decoded':data[off:off+20].hex(), 'fflz_header':{'unpacked_bytes':unpacked,'packed_including_header':packed,'pages':pages,'page_size':page,'alignment':alignment}, 'packed_sha256':H(data[off:off+packed]),'unpacked_sha256':H(b),'unpacked_first_64':b[:64].hex(),'header_8_u64le':[hex(x) for x in u64], 'strings':{s.hex()+' '+repr(s):occurrences(b,s) for s in strings}, 'early_adrp_add_refs':refs, 'display_table_0x14a3b8_hex':b[0x14a3b8:0x14a568].hex(), 'neighboring_fflz_comparison':comparisons,'literal_dat_search_capped_100':needles,'dat_xor_bytes_0x120340_0x1203c0':data[0x120340:0x1203c0].hex(),'source_sha256_after':H(src.read_bytes())}
assert result['source_sha256_after']==initial
(HERE / 'доказательства.json').write_text(json.dumps(result,ensure_ascii=False,indent=2)+'\n',encoding='utf-8')
print(json.dumps({'header':result['fflz_header'], 'u64':result['header_8_u64le'],'refs':refs,'comparisons':comparisons,'literals':needles},ensure_ascii=False,indent=2))
