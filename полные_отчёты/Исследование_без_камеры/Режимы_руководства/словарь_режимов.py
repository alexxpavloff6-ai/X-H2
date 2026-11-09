"""Только чтение DAT; пары из таблицы указатель+uint64 в распакованном блоке.
Запуск из любой папки: python путь/словарь_режимов.py. Результат рядом со сценарием.
"""
import sys
sys.dont_write_bytecode = True
from pathlib import Path
import hashlib
import importlib.util
import json
import struct

HERE = Path(__file__).resolve().parent
ROOT = HERE.parents[2]
base_path = ROOT / 'Анализ_прошивки' / 'анализ_файла.py'
spec = importlib.util.spec_from_file_location('firmware_base', base_path)
base = importlib.util.module_from_spec(spec)
spec.loader.exec_module(base)
FILES = {
    'X-H2 5.30': ('FIRMWARE/ver 5.30/FWUP0028.DAT', 0x840274),
    'X-H2S 7.30': ('Firmware на прочиеFuji/FWUP0027.DAT', 0x840274),
    'X-T5 4.31': ('Firmware на прочиеFuji/FWUP0030.DAT', 0x820274),
    'X100VI 1.31': ('Firmware на прочиеFuji/FPUPDATE.DAT', 0x10e02bc),
}
LABELS = ['UI_FOCUS_MODE_CAF', 'UI_FOCUS_MODE_SAF', 'UI_FOCUS_MODE_MF',
          'UI_SHUTTER_TYPE_MECHA', 'UI_SHUTTER_TYPE_ELE', 'UI_SHUTTER_TYPE_SME',
          'UI_SHUTTER_TYPE_AUTO', 'UI_SHUTTER_TYPE_SME_MECHA',
          'UI_SHUTTER_TYPE_SME_MECHA_ELE', 'UI_SHUTTER_TYPE_SME_ELE',
          'UI_PERFORMANCE_AF_SPEED_UP', 'UI_FUNC_SET_PERFORMANCE',
          'BKUP_PERFORMANCE_AF_SPEED_UP', 'UI_FOCUS_MODE_NOT_A_REAL_MODE']

def sha(path):
    h = hashlib.sha256()
    with path.open('rb') as f:
        for chunk in iter(lambda: f.read(4 * 1024 * 1024), b''):
            h.update(chunk)
    return h.hexdigest()

def find_all(data, needle):
    p = 0
    while True:
        p = data.find(needle, p)
        if p < 0:
            return
        yield p
        p += 1

def main():
    result = {'method': 'В указанном распакованном блоке поиск полного ASCII имени с NUL и всех выровненных по 8 смещений указателей base+offset; следующее uint64 — значение таблицы, не доказанное значение состояния камеры.', 'labels': LABELS, 'dependency': str(base_path.relative_to(ROOT)), 'dependency_sha256_before': sha(base_path), 'models': {}}
    for model, (relative, offset) in FILES.items():
        path = ROOT / relative
        before = sha(path)
        data = path.read_bytes().translate(base.TRANSLATION)
        block = base.unpack_fflz(data, offset)
        del data
        address_base = struct.unpack_from('<Q', block, 8)[0]
        entries = {}
        for name in LABELS:
            matches = []
            for s in find_all(block, name.encode('ascii') + b'\0'):
                for p in find_all(block, struct.pack('<Q', address_base + s)):
                    if p % 8 == 0 and p + 16 <= len(block):
                        matches.append({'string_offset': hex(s), 'record_offset': hex(p), 'value': struct.unpack_from('<Q', block, p + 8)[0]})
            entries[name] = matches
        after = sha(path)
        if before != after:
            raise RuntimeError('Изменился вход: ' + relative)
        result['models'][model] = {'input': relative, 'sha256_before': before, 'sha256_after': after, 'packed_block_offset': hex(offset), 'unpacked_size': len(block), 'unpacked_sha256': hashlib.sha256(block).hexdigest(), 'virtual_base': hex(address_base), 'entries': entries}
        print(model, 'готово', flush=True)
    result['dependency_sha256_after'] = sha(base_path)
    if result['dependency_sha256_before'] != result['dependency_sha256_after']:
        raise RuntimeError('Изменился распаковщик')
    (HERE / 'Словарь_режимов.json').write_text(json.dumps(result, ensure_ascii=False, indent=2) + '\n', encoding='utf-8')

if __name__ == '__main__':
    main()
