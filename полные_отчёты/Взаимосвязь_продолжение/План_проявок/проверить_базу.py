"""Validate historical one-factor controls for planned two-factor experiments.
Reads existing local JSON and inputs; never modifies user files.
"""
from pathlib import Path
import hashlib
import json

HERE = Path(__file__).resolve().parent
ANALYSIS = HERE.parents[1]
ROOT = ANALYSIS.parent
series = json.loads((ANALYSIS / 'Проявка_0296_серия_2/Метаданные/метаданные.json').read_text(encoding='utf-8'))['files']
first = json.loads((ANALYSIS / 'Проявка_0296/Метаданные/метаданные.json').read_text(encoding='utf-8'))['files']
paths = {'DSCF0300.JPG': ROOT/'Тестовые фото/Доработка 296 в камере/DSCF0300.JPG',
         'DSCF0301.JPG': ROOT/'Тестовые фото/Доработка 296 в камере/DSCF0301.JPG'}
paths.update({f'DSCF{i:04d}.JPG': ROOT/'Тестовые фото/Доработка 296 в камере/Доработка 2'/f'DSCF{i:04d}.JPG' for i in (303,304,305,307,308,309,310)})

def sha(path):
    h = hashlib.sha256()
    with path.open('rb') as f:
        for chunk in iter(lambda: f.read(1024*1024), b''):
            h.update(chunk)
    return h.hexdigest()

def numeric(name):
    tags = (first if name == 'DSCF0301.JPG' else series)[name]['numeric']
    def get(key):
        for candidate in ('FujiFilm:'+key, 'FujiFilm:Copy1:'+key):
            if candidate in tags:
                return tags[candidate]
        raise KeyError(f'{name}: {key}')
    fields = ('FilmMode','Saturation','HighlightTone','ShadowTone','ColorChromeEffect',
              'ColorChromeFXBlue','ColorTemperature','WhiteBalanceFineTune','Clarity','Sharpness','NoiseReduction')
    return {key:get(key) for key in fields}

source_hashes = {}
for name, path in paths.items():
    observed = sha(path)
    expected = (first if name == 'DSCF0301.JPG' else series)[name]['sha256_before']
    if observed != expected:
        raise ValueError(f'Input does not match previously extracted metadata: {name}')
    source_hashes[name] = observed
base = numeric('DSCF0300.JPG')
expected_changes = {'DSCF0301.JPG': {'Saturation': 0},
                    'DSCF0303.JPG': {'HighlightTone': 0}, 'DSCF0304.JPG': {'ShadowTone': 0},
                    'DSCF0305.JPG': {'ColorChromeEffect': 0}, 'DSCF0307.JPG': {'ColorTemperature': 5000},
                    'DSCF0308.JPG': {'Clarity': 0}, 'DSCF0309.JPG': {'Sharpness': 3},
                    'DSCF0310.JPG': {'NoiseReduction': 0}}
controls = {}
for name, target in expected_changes.items():
    tags = numeric(name)
    actual = {key:value for key,value in tags.items() if base[key] != value}
    if actual != target:
        raise ValueError(f'Unexpected selected-tag differences: {name}: {actual} != {target}')
    controls[name] = actual
plans = [
    {'id':'A0','purpose':'repeat baseline 0300','settings_changes':{},'control_files':['DSCF0300.JPG']},
    {'id':'A1','purpose':'highlight × shadow','settings_changes':{'HighlightTone':0,'ShadowTone':0},'control_files':['DSCF0303.JPG','DSCF0304.JPG','DSCF0300.JPG']},
    {'id':'A2','purpose':'color × Color Chrome Effect','settings_changes':{'Saturation':0,'ColorChromeEffect':0},'control_files':['DSCF0301.JPG','DSCF0305.JPG','DSCF0300.JPG']},
    {'id':'A3','purpose':'WB × Color Chrome Effect','settings_changes':{'ColorTemperature':5000,'ColorChromeEffect':0},'control_files':['DSCF0307.JPG','DSCF0305.JPG','DSCF0300.JPG']},
    {'id':'A4','purpose':'clarity × sharpness','settings_changes':{'Clarity':0,'Sharpness':3},'control_files':['DSCF0308.JPG','DSCF0309.JPG','DSCF0300.JPG']},
    {'id':'A5','purpose':'sharpness × noise reduction','settings_changes':{'Sharpness':3,'NoiseReduction':0},'control_files':['DSCF0309.JPG','DSCF0310.JPG','DSCF0300.JPG']},
]
if any(sha(path) != source_hashes[name] for name,path in paths.items()):
    raise RuntimeError('Input changed during validation')
output = {'method':'Selected Fuji numeric tags taken from prior ExifTool JSON, checked against SHA-256 of existing files. Selected settings only, not all tags or hidden state. RAW identity based on owner report. A0 is a recommended repeat; one common control does not prove repeatability of each condition.', 'baseline_selected_tags':base,'validated_single_factor_controls':controls,'old_source_sha256_before_after':source_hashes,'new_0296_outputs':plans,
'blue_scene_plan':{'id':'B1-B5','design':'new or existing RAW with blue, four Chrome/FX Blue combinations plus repeat Strong/Strong; all other settings and same RAW held constant. No claim this RAW has yet been supplied.'}}
(HERE/'план.json').write_text(json.dumps(output,ensure_ascii=False,indent=2)+'\n',encoding='utf-8')
print('Valid existing controls:',len(controls),'planned 0296 JPEGs:',len(plans),'blue-scene JPEGs: 5')
