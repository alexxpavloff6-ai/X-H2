#!/usr/bin/env python3
"""Только чтение тестовой серии и существующих метаданных; вывод без изображений и приватных тегов."""
import hashlib
import itertools
import json
from pathlib import Path

ROOT = Path(__file__).resolve().parents[4]
SERIES = ROOT / 'Тестовые фото'
META = ROOT / 'Анализ_прошивки/Проявка_0296/Метаданные/метаданные.json'
OUT = Path(__file__).with_name('матрица.json')
RAW = 'DSCF0296.RAF'
JPEGS = ['DSCF0300.JPG', 'DSCF0301.JPG', 'DSCF0302.JPG']
TAGS = {
    'света': ['FujiFilm:HighlightTone'],
    'тени': ['FujiFilm:ShadowTone'],
    'Color Chrome': ['FujiFilm:ColorChromeEffect'],
    'FX Blue': ['FujiFilm:ColorChromeFXBlue'],
    'WB': ['FujiFilm:WhiteBalance', 'FujiFilm:ColorTemperature', 'FujiFilm:WhiteBalanceFineTune'],
    'clarity': ['FujiFilm:Clarity'],
    'sharpness': ['FujiFilm:Sharpness'],
    'noise reduction': ['FujiFilm:NoiseReduction'],
    'color': ['FujiFilm:Saturation'],
}
PLAN = {
    'света': ['TONE CURVE / HIGHLIGHT', '+1.5', '0'],
    'тени': ['TONE CURVE / SHADOW', '+0.5', '0'],
    'Color Chrome': ['COLOR CHROME EFFECT', 'STRONG', 'OFF'],
    'FX Blue': ['COLOR CHROME FX BLUE', 'STRONG', 'OFF'],
    'WB': ['WHITE BALANCE / COLOR TEMPERATURE', '5750 K', '5000 K'],
    'clarity': ['CLARITY', '+3', '0'],
    'sharpness': ['SHARPNESS', '-1', '0'],
    'noise reduction': ['HIGH ISO NR', '-4', '0'],
}

def sha(path):
    h = hashlib.sha256()
    with path.open('rb') as f:
        for chunk in iter(lambda: f.read(1024 * 1024), b''):
            h.update(chunk)
    return h.hexdigest()

def inventory():
    return sorted(p for p in SERIES.rglob('*') if p.is_file())

def main():
    paths = inventory()
    before = {str(p.relative_to(ROOT)).replace('\\', '/'): sha(p) for p in paths}
    meta_before = sha(META)
    metadata = json.loads(META.read_text(encoding='utf-8'))
    files = metadata['files']
    for name in [RAW] + JPEGS:
        matches = [p for p in paths if p.name == name]
        if len(matches) != 1:
            raise RuntimeError(f'Неоднозначный или отсутствующий файл: {name}')
        key = str(matches[0].relative_to(ROOT)).replace('\\', '/')
        if before[key] != files[name]['sha256_after']:
            raise RuntimeError(f'Метаданные относятся к другим байтам: {name}')
    values = {name: {label: {tag: {'numeric': files[name]['numeric'].get(tag), 'display': files[name]['display'].get(tag)} for tag in tags} for label, tags in TAGS.items()} for name in [RAW] + JPEGS}
    matrix = []
    for label in TAGS:
        pairs = []
        for a, b in itertools.combinations(JPEGS, 2):
            av = [files[a]['numeric'].get(t) for t in TAGS[label]]
            bv = [files[b]['numeric'].get(t) for t in TAGS[label]]
            others_equal = all(files[a]['numeric'].get(t) == files[b]['numeric'].get(t) and files[a]['numeric'].get(t) is not None for other, tags in TAGS.items() if other != label for t in tags)
            different = all(v is not None for v in av + bv) and av != bv
            pairs.append({'a': a, 'b': b, 'target_differs': different, 'other_matrix_fields_equal': others_equal, 'available_candidate': different and others_equal})
        row = {'parameter': label, 'pairs': pairs, 'available': any(p['available_candidate'] for p in pairs)}
        if label in PLAN:
            menu, base, target = PLAN[label]
            row['future_single_change'] = {'menu': menu, 'baseline': base, 'target': target, 'status': 'ожидается JPEG владельца; доступность меню не проверена на камере'}
        matrix.append(row)
    after_paths = inventory()
    if paths != after_paths:
        raise RuntimeError('Состав тестовой серии изменился во время анализа')
    after = {str(p.relative_to(ROOT)).replace('\\', '/'): sha(p) for p in after_paths}
    meta_after = sha(META)
    if before != after or meta_before != meta_after:
        raise RuntimeError('Вход изменился во время анализа; результат не записан')
    result = {
        'method': {'source_relationship': 'Владелец сообщил, что 0300/0301/0302 — камерные проявки 0296; EXIF согласуется, но сам по себе происхождение не доказывает.', 'comparability': 'Кандидат сравнения только для JPEG заявленного общего RAW с различием целевого поля и равенством остальных полей матрицы; скрытые настройки не исключены.', 'metadata_source': str(META.relative_to(ROOT)).replace('\\', '/'), 'metadata_sha256_before': meta_before, 'metadata_sha256_after': meta_after, 'metadata_exiftool_version': metadata['method']['exiftool_version'], 'numeric_convention': '-n ExifTool: ValueConv, не обязательно сырые байты', 'privacy': 'Только имена файлов, хеши и выбранные неприватные теги; изображения и приватные теги не сохраняются.'},
        'input_inventory': [{'path': key, 'sha256_before': before[key], 'sha256_after': after[key]} for key in before],
        'values': values,
        'comparison_matrix': matrix,
        'future_baseline': {'status': 'отсутствует; создать владельцу', 'source': RAW, 'restore': 'REFLECT SHOOTING COND. перед каждой проявкой', 'common_output': 'JPEG, O 3:2 7728x5152, FINE; одинаково для всей новой серии', 'note': 'Базовая проявка и восемь одиночных изменений; 0300 не считать автоматически идентичной новой базе.'},
        'manual': {'raw_conversion': 'https://fujifilm-dsc.com/en-int/manual/x-h2/playback/menu_playback/index.html#raw_conversion', 'image_quality': 'https://fujifilm-dsc.com/en-int/manual/x-h2/menu_shooting/image_quality_setting/index.html', 'caveat': 'Some settings may be unavailable depending on the options chosen when the picture was taken.'},
    }
    OUT.write_text(json.dumps(result, ensure_ascii=False, indent=2) + '\n', encoding='utf-8')
    print('Создана матрица:', OUT)

if __name__ == '__main__':
    main()
