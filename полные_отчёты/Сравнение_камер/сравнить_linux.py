"""Сравнение ранее извлечённых каталогов CPIO по путям и хешам."""
from pathlib import Path
import csv
import json

HERE = Path(__file__).resolve().parent
FILES = {'X-H2S': HERE / 'X-H2S/linux_cpio.tsv', 'X-T5': HERE / 'X-T5/каталог_CPIO.tsv', 'X100VI': HERE / 'X100VI/Linux_cpio.tsv'}

def main():
    tables = {}
    for model, path in FILES.items():
        with path.open(encoding='utf-8-sig', newline='') as stream:
            rows = list(csv.DictReader(stream, delimiter='\t'))
        tables[model] = {r['path']: r for r in rows}
        if len(tables[model]) != len(rows):
            raise ValueError(f'Повторяющийся путь в {model}')
    source = tables['X-H2S']
    result = {}
    for model in ['X-T5', 'X100VI']:
        other = tables[model]
        common = set(source) & set(other)
        regular = sorted(k for k in common if source[k]['kind'] == other[k]['kind'] == 'обычный файл')
        identical = [k for k in regular if source[k]['sha256'] and source[k]['sha256'] == other[k]['sha256']]
        identical_set = set(identical)
        different = [k for k in regular if k not in identical_set]
        result[model] = {'common_paths': len(common), 'common_regular_files': len(regular), 'identical_files': len(identical), 'different_files': different, 'only_xh2s': sorted(set(source)-set(other)), 'only_other': sorted(set(other)-set(source))}
    (HERE/'Сравнение_Linux.json').write_text(json.dumps(result, ensure_ascii=False, indent=2)+'\n', encoding='utf-8')
    print(json.dumps({m:{k:v for k,v in r.items() if isinstance(v,int)} for m,r in result.items()},ensure_ascii=False))

if __name__ == '__main__':
    main()
