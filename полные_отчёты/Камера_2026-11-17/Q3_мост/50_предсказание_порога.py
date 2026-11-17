# -*- coding: utf-8 -*-
"""Q3 4-й круг, шаг 50: ПРЕДСКАЗАНИЕ порога (ДО снимков 09-11).
fieldB и флаг для каждой стандартной выдержки X-H2 1/3 EV от 1/250 до 1/32000.
Модель: fieldB = знаменатель/100 (категории кодировщика 0x14F396C совпадают 18/18);
флаг = table_0x3456B20[6*min(fieldB,40)+shutter_type]==2 (VM 0x2F85F3C)."""
import json
import sys
from pathlib import Path

HERE = Path(__file__).resolve().parent
sys.path.insert(0, str(HERE))
from q3common import load  # noqa: E402
from unicorn import Uc, UC_ARCH_ARM64, UC_MODE_LITTLE_ENDIAN  # noqa: E402
from unicorn.arm64_const import (UC_ARM64_REG_SP, UC_ARM64_REG_LR, UC_ARM64_REG_X0, UC_ARM64_REG_X1)  # noqa: E402

b0 = load('X-H2', 'old', 0)
b1 = load('X-H2', 'old', 1)

# 1/3 EV знаменатели X-H2 от 1/250 до 1/32000 (ES-диапазон)
DENOMS = [250, 320, 400, 500, 640, 800, 1000, 1250, 1600, 2000, 2500, 3200,
          4000, 5000, 6400, 8000, 10000, 12800, 16000, 20000, 25600, 32000]
# категории кодировщика (code 0..17) и соответствующие знаменатели
ENC_CATS = [3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 15, 20, 30, 40, 60, 80, 160]
ENC_DENOMS = [c * 100 for c in ENC_CATS]


def pagesz(n):
    return (n + 0xFFF) & ~0xFFF


mu = Uc(UC_ARCH_ARM64, UC_MODE_LITTLE_ENDIAN)
mu.mem_map(b0.base, pagesz(len(b0.data)))
mu.mem_write(b0.base, b0.data)
mu.mem_map(b1.base, pagesz(len(b1.data)))
mu.mem_write(b1.base, b1.data)
mu.mem_map(0x10000000, 0x10000)


def table_vm(fieldB, shutter_type):
    mu.reg_write(UC_ARM64_REG_X0, fieldB)
    mu.reg_write(UC_ARM64_REG_X1, shutter_type)
    mu.reg_write(UC_ARM64_REG_LR, 0x10000000)
    mu.reg_write(UC_ARM64_REG_SP, 0x10008000)
    mu.emu_start(0x2F85F3C, 0x10000000, count=50)
    return mu.reg_read(UC_ARM64_REG_X0) & 0xFFFFFFFF


def nearest_cat(fieldB):
    # ближайшая категория кодировщика (квантование), для справки
    return min(ENC_CATS, key=lambda c: abs(c - fieldB))


rows = []
prev_flag = None
boundary = None
nonmono = []
for d in DENOMS:
    fb_cont = d // 100                      # непрерывная модель fieldB = знаменатель/100
    fb_table = min(fb_cont, 40)             # таблица клампует до 40
    cat = nearest_cat(fb_cont)
    tab_es = table_vm(fb_table, 1)
    flag_es = 1 if tab_es == 2 else 0
    flag_ms = 1 if table_vm(fb_table, 0) == 2 else 0
    flag_ef = 1 if table_vm(fb_table, 3) == 2 else 0
    # для выдержек быстрее 1/16000 code может кламповаться на 17 (fieldB 160) -> флаг 1,
    # либо code>17 -> fieldB 0 -> флаг 0 (немонотонность, Г)
    fast_ambiguous = d > 16000
    rows.append({'denominator': d, 'speed': f'1/{d}', 'fieldB_continuous': fb_cont,
                 'fieldB_table_clamped': fb_table, 'nearest_encoder_category': cat,
                 'table_value_ES': tab_es, 'flag_ES': flag_es, 'flag_MS': flag_ms, 'flag_EF': flag_ef,
                 'faster_than_1_16000_ambiguous': fast_ambiguous})
    if prev_flag == 0 and flag_es == 1 and boundary is None:
        boundary = f'1/{d}'
    if prev_flag == 1 and flag_es == 0:
        nonmono.append(f'1/{d}')
    prev_flag = flag_es

prediction = {
    'round': 4, 'type': 'prediction_before_snapshots', 'date': '2026-11-17',
    'firmware': 'X-H2 5.30',
    'model': {
        'fieldB': 'знаменатель выдержки / 100 (speed_output 0x18C // 10000)',
        'fieldB_level': 'К (семантика); Д для 18 категорий кодировщика 0x14F396C (jump-table 0x1AE2F14), точное совпадение знаменатель/100',
        'flag_rule': 'table_0x3456B20[6*min(fieldB,40)+shutter_type]==2; VM 0x2F85F3C',
        'flag_rule_level': 'Д',
        'shutter_type': 'фактический затвор 0x1A8: 0 MS, 1 ES, 3 EF; флаг только при ES==1',
        'gate_fieldA': 'CH (0x68C==21) + IMAGE DISP CONTINUOUS (0x29B==2); предикат 0x2FE35D4 гейты ctx 0x4D35710 биты 4/12/13/14',
        'speed_to_code_gap': 'точное отображение выдержка->code inner[0x784] статически не прослежено (К); квантование к 18 категориям кодировщика',
    },
    'threshold': {
        'fieldB_threshold': 6,
        'speed_threshold': '1/600 (знаменатель 600)',
        'first_1_3EV_speed_with_flag_1': boundary,
        'boundary_pair': '1/500 (fieldB 5, флаг 0) -> 1/640 (fieldB 6, флаг 1)',
        'refines_K2': 'K2 BACKUP-условие <=1/8000 уже реального порога прошивки <=1/600',
    },
    'monotonicity': {
        'continuous_model': 'монотонно: флаг 1 для всех ES выдержек >=1/640 (в CH+CONT)',
        'non_monotonic_points_continuous': nonmono,
        'fast_speed_caveat': 'для >1/16000 (1/20000..1/32000): если code клампуется на 17 -> fieldB 160 -> флаг 1 (монотонно); если code>17 -> fieldB 0 -> флаг 0 (немонотонность). Уровень Г, склоняемся к монотонно (дефект воспроизведён на 1/16000, физически быстрее тоже должен триггерить).',
    },
    'owner_test_predictions': {
        '08_1-500': {'note': 'блоб 08 фактически EF (миссет); 08B = ES', 'flag_ES_prediction': 0},
        '08B_1-500': {'config': 'CH,ES,1/500,CONT', 'fieldB': 5, 'flag_prediction': 0},
        '09_1-640': {'config': 'CH,ES,1/640,CONT', 'fieldB': 6, 'flag_prediction': 1, 'critical': 'граничный тест: опровергает K2 <=1/8000 если дефект есть'},
        '10_1-1000': {'config': 'CH,ES,1/1000,CONT', 'fieldB': 10, 'flag_prediction': 1},
        '11_1-4000': {'config': 'CH,ES,1/4000,CONT', 'fieldB': 40, 'flag_prediction': 1},
    },
    'table': rows,
}
(HERE / 'предсказание_порога.json').write_text(json.dumps(prediction, ensure_ascii=False, indent=2) + '\n', encoding='utf-8')
print('граница 0->1 (первая 1/3 EV с флагом 1):', boundary)
print('немонотонность (непрерывная модель):', nonmono or 'нет')
print('\nspeed | fieldB | cat | flag_ES | flag_MS | flag_EF | >1/16000')
for r in rows:
    print(f"{r['speed']:8s} | {r['fieldB_continuous']:6d} | {r['nearest_encoder_category']:3d} | "
          f"{r['flag_ES']} | {r['flag_MS']} | {r['flag_EF']} | {'?' if r['faster_than_1_16000_ambiguous'] else ''}")
