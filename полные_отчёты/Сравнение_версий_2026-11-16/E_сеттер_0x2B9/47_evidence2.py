# -*- coding: utf-8 -*-
"""E47: дополнение доказательства.json — MODE_RECORD резолвер (три модели), T5 0x39C0, H2S x20."""
import sys, json
sys.path.insert(0, r'<корень проекта>\Анализ_прошивки\Сравнение_версий_2026-11-16\E_сеттер_0x2B9')
from ecommon import *  # noqa
from pathlib import Path

HERE = Path(__file__).resolve().parent
ev = json.loads((HERE / 'доказательства.json').read_text(encoding='utf8'))
b0 = load('X-H2', 'new', 0)
b1 = load('X-H2', 'new', 1)


def code(blk, va, n):
    return dis(blk, va, n)


ev['14_MODE_RECORD_резолвер'] = {
    'уровень': 'Д',
    'что': 'код [ctx+0x3978] — это MODE_RECORD; имена берутся из цепочки cmp/adrp+add в блоке 0',
    'X-H2_5.33': {
        'вход': '0x1141ee0',
        '0x00': {'body': '0x1142230', 'str': '0x1640dd8', 'name': 'MODE_RECORD_AUTO'},
        '0x21': {'body': '0x11423bc', 'str': '0x1641178', 'name': 'MODE_RECORD_PROGRAM'},
        '0x22': {'body': '0x11423c8', 'str': '0x1641190', 'name': 'MODE_RECORD_SHUTTER'},
        '0x23': {'body': '0x11423d4', 'str': '0x16411a8', 'name': 'MODE_RECORD_APERTURE'},
        '0x24': {'body': '0x11423e0', 'str': '0x16411c0', 'name': 'MODE_RECORD_MANUAL'},
        '0x2C': {'body': '0x1142440', 'str': '0x1641280', 'name': 'MODE_RECORD_HDR'},
        '0x2D': {'body': '0x114244c', 'str': '0x1641290', 'name': 'MODE_RECORD_MOTIONJPEG'},
    },
    'X-H2S_7.31': {'0x24': '0x1461e84 -> 0x196b7b8 MODE_RECORD_MANUAL',
                   '0x2C': '0x1461ee4 -> 0x196b878 MODE_RECORD_HDR',
                   '0x2D': '0x1461ef0 -> 0x196b888 MODE_RECORD_MOTIONJPEG'},
    'X-T5_4.32': {'0x24': '0x11423f0 -> 0x163f7f8 MODE_RECORD_MANUAL',
                  '0x2C': '0x1142450 -> 0x163f8b8 MODE_RECORD_HDR',
                  '0x2D': '0x114245c -> 0x163f8c8 MODE_RECORD_MOTIONJPEG'},
    'инструкции_0x2C': [code(b0, 0x1142440, 2)],
    'следствие': '0x2C в recfCalcRecifParam = HDR (многокадровая композиция), не ISO BKT/FSIM BKT',
}

ev['15_X-T5_поле_режима'] = {
    'уровень': 'Д (смещение), Д-отриц. (писатель 0x2C)',
    'функция_recfCalcRecifParam': '0x2d131a0 (строка "recfCalcRecifParam()" 0x3322850)',
    'поле': 'ctx+0x39C0, подтип ctx+0x39C4',
    'ветки': [code(b1 if False else load('X-T5', 'new', 1), 0x2d132dc, 6)],
    'обращений_к_0x39c0': 272,
    'записей': 6,
    'писатели': ['0x2d59c20 str w0,[x20,#0x39c0] (0x21/0x22/0x23/0x24 по ctx+0x39c4)',
                 '0x2d59c2c', '0x2d59c38', '0x2d9e940', '0x2d9ea48', '0x2d9ea64'],
    'вывод': 'записи 0x2C нет; копии job+0x144 -> ctx+0x39C0 нет; HDR-режим в T5 приходит не из этого образа',
}

ev['16_X-H2S_прямой_путь'] = {
    'уровень': 'Д',
    'функция': '0x3177180(w0=ctx, w1=src, x2=arg2)',
    'инструкции': [code(load('X-H2S', 'new', 1), 0x31771c0, 10)],
    'x20': 'аргумент x1 (mov x20,x1 в 0x3177198); вызывающие 0x315ee04/0x315f14c/0x315f9d8/0x3160250 передают структуру-источник',
    'копия': 'ctx+0x3978 = src+0x14 (0x31771dc), зеркала в ctx+0x4000+0x34 и +0x1c28',
    'вторая_копия': 'job+0x144 -> ctx+0x3978 в 0x33a073c/0x33a0740',
}

(HERE / 'доказательства.json').write_text(json.dumps(ev, ensure_ascii=False, indent=1), encoding='utf8')
print('OK, разделов:', len(ev))
