"""Сопоставление таблиц именованных параметров. Прошивки только читаются."""
from pathlib import Path
import hashlib
import importlib.util
import json
import struct

HERE = Path(__file__).resolve().parent
ROOT = HERE.parent.parent
spec = importlib.util.spec_from_file_location('firmware_base', HERE.parent / 'анализ_файла.py')
base = importlib.util.module_from_spec(spec)
spec.loader.exec_module(base)
FILES = {
    'X-H2': (ROOT / 'FIRMWARE/ver 5.30/FWUP0028.DAT', 0x840274),
    'X-H2S': (ROOT / 'Firmware на прочиеFuji/FWUP0027.DAT', 0x840274),
    'X-T5': (ROOT / 'Firmware на прочиеFuji/FWUP0030.DAT', 0x820274),
    'X100VI': (ROOT / 'Firmware на прочиеFuji/FPUPDATE.DAT', 0x10e02bc),
}
LABELS = ['UI_SETP_FILM_SIM', 'UI_SETP_WB', 'UI_SETP_WB_TUNING_R', 'UI_SETP_WB_TUNING_B', 'UI_SETP_NR', 'UI_SETP_CLARITY', 'UI_SETP_DRANGE', 'UI_SETP_STILLCOLOR', 'UI_SETP_SHARPNESS', 'UI_SETP_HIGHLIGHT', 'UI_SETP_SHADOW', 'UI_SETP_GRAIN', 'UI_SETP_GRAIN_SIZE']


def locate(block, address_base, name):
    string = name.encode('ascii') + b'\0'
    s = block.find(string)
    if s < 0:
        raise ValueError(f'Строка не найдена: {name}')
    pointer = struct.pack('<Q', address_base + s)
    candidates = []
    pos = 0
    while True:
        pos = block.find(pointer, pos)
        if pos < 0:
            break
        if pos % 8 == 0 and pos + 16 <= len(block):
            candidates.append((pos, struct.unpack_from('<Q', block, pos + 8)[0]))
        pos += 1
    if len(candidates) != 1:
        raise ValueError(f'Неоднозначная запись {name}: {candidates}')
    return {'string_offset': hex(s), 'record_offset': hex(candidates[0][0]), 'value': candidates[0][1]}


def main():
    results = {}
    for model, (path, offset) in FILES.items():
        raw = path.read_bytes()
        sha = hashlib.sha256(raw).hexdigest()
        decoded = raw.translate(base.TRANSLATION)
        block = base.unpack_fflz(decoded, offset)
        address_base = struct.unpack_from('<Q', block, 8)[0]
        first = locate(block, address_base, 'UI_FILM_SIM_STD')
        start = int(first['record_offset'], 16)
        film = []
        for index in range(26):
            pos = start + index * 16
            ptr, value = struct.unpack_from('<QQ', block, pos)
            str_off = ptr - address_base
            if not 0 <= str_off < len(block):
                raise ValueError(f'{model}: неверный указатель')
            end = block.find(b'\0', str_off, min(str_off + 150, len(block)))
            if end < 0:
                raise ValueError(f'{model}: нет конца строки')
            name = block[str_off:end].decode('ascii')
            if not name.startswith('UI_FILM_SIM_') or value != index:
                raise ValueError(f'{model}: неожиданная запись {index}: {name}, {value}')
            film.append({'name': name, 'value': value, 'record_offset': hex(pos), 'string_offset': hex(str_off)})
        settings = {label: locate(block, address_base, label) for label in LABELS}
        assert hashlib.sha256(path.read_bytes()).hexdigest() == sha
        results[model] = {'path': str(path.relative_to(ROOT)), 'sha256': sha, 'packed_block_offset': hex(offset), 'decoded_block_sha256': hashlib.sha256(block).hexdigest(), 'address_base': hex(address_base), 'film': film, 'settings': settings}
    expected = [(r['name'], r['value']) for r in results['X-H2']['film']]
    for model, result in results.items():
        if [(r['name'], r['value']) for r in result['film']] != expected:
            raise ValueError(f'{model}: словарь отличается')
    (HERE / 'Сравнение_словарей.json').write_text(json.dumps(results, ensure_ascii=False, indent=2) + '\n', encoding='utf-8')
    lines = ['# Сравнение таблиц настроек четырёх камер', '', 'Прошивки только читались; SHA-256 файлов проверен до и после чтения. Таблицы извлечены из распакованного блока FFLZ по указателям и целочисленным значениям, а не просто по совпадению строк.', '', '| Камера | Смещение FFLZ в DAT | База адресов блока | Смещение первой записи Film Simulation в распакованном блоке |', '|---|---:|---:|---:|']
    for model, r in results.items():
        lines.append(f"| {model} | {r['packed_block_offset']} | {r['address_base']} | {r['film'][0]['record_offset']} |")
    lines += ['', '## Имитации плёнки', '', 'Все 26 записей в четырёх файлах содержат одинаковые пары внутреннего имени и кода:', '', '| Код | Внутреннее имя |', '|---:|---|']
    for row in results['X-H2']['film']:
        lines.append(f"| {row['value']} | `{row['name']}` |")
    lines += ['', 'Совпадение словаря не устанавливает доступность каждого режима в меню конкретной камеры и не доказывает одинаковое цветопреобразование или совпадение коэффициентов.', '', '## Идентификаторы настроек', '', 'Значения в проверенных словарях: одинаковое имя настройки не всегда имеет одинаковый внутренний идентификатор.', '', '| Внутреннее имя | X-H2 | X-H2S | X-T5 | X100VI |', '|---|---:|---:|---:|---:|']
    for label in LABELS:
        vals = ' | '.join(str(results[m]['settings'][label]['value']) for m in FILES)
        lines.append(f'| `{label}` | {vals} |')
    lines += ['', 'Это идентификаторы из конкретных таблиц рассматриваемых сборок, не доказанные универсальные адреса или значения цвета. Прямой перенос идентификаторов между моделями небезопасен.', '', '## Воспроизведение и границы', '', 'Запуск: `python Анализ_прошивки/Сравнение_камер/сравнить_словари.py`. Машиночитаемые смещения, хеши и записи — `Сравнение_словарей.json`. Не выполнялись запуск камеры, восстановление исходного кода или полное сравнение алгоритмов.', '']
    (HERE / 'Сравнение_цветовых_словарей.md').write_text('\n'.join(lines), encoding='utf-8')
    print(json.dumps({'models': list(results), 'identical_film_records': len(expected), 'settings_per_model': len(LABELS), 'unchanged': True}, ensure_ascii=False))


if __name__ == '__main__':
    main()
