import json
import struct
import sys
from pathlib import Path

HERE = Path(__file__).resolve().parent
ROOT = HERE.parents[2]
sys.path.insert(0, str(HERE.parents[1] / 'Сравнение_версий_2026-11-16'))
import fwcommon

b0 = fwcommon.load('X-H2', 'old', 0)
b1 = fwcommon.load('X-H2', 'old', 1)


def u16(block, address):
    return struct.unpack_from('<H', block.data, block.off(address))[0]


catalog_path = ROOT / 'Внешние_репозитории/fujimod/catalog/firmware/xh2/5.30/ui-setting-names.generated.json'
catalog = json.loads(catalog_path.read_text(encoding='utf-8'))['ui_setting_names']
assert catalog['UI_SETP_CONTINUOUS'] == 0x858
assert catalog['UI_SETP_SHUTTER_TYPE'] == 0x827
assert catalog['UI_SETP_SHUTTER_SPEED'] == 0x89E
assert catalog['UI_SETP_PC_EXPOSURETIME'] == 0x991
assert catalog['UI_SETP_REC_VIEW'] == 0xB


def rows(setting_id, limit=40):
    pointer = b0.u64(0x1BD5AB8 + 8 * setting_id)
    assert pointer
    result = []
    for index in range(limit):
        values = struct.unpack_from('<4I', b0.data, b0.off(pointer) + 16 * index)
        if values[0] == 0xFFFF:
            break
        result.append({'row': index, 'values': [hex(v) for v in values]})
    return {'setting_id': hex(setting_id), 'table': hex(pointer), 'rows': result}


continuous = rows(0x858)
shutter_type = rows(0x827)
rec_view = rows(0xB)
assert continuous['table'] == '0x17572a0'
assert shutter_type['table'] == '0x176d340'
assert rec_view['table'] == '0x176c090'
assert continuous['rows'][0]['values'][3] == '0x4'
assert continuous['rows'][21]['values'][3] == '0x2'
assert continuous['rows'][23]['values'][3] == '0x3'
assert shutter_type['rows'][0]['values'][2] == '0x0'
assert shutter_type['rows'][1]['values'][2] == '0x1'
assert shutter_type['rows'][3]['values'][2] == '0x2'
assert rec_view['rows'][0]['values'][3] == '0xffff'
assert rec_view['rows'][5]['values'][3] == '0x0'

property_list = [u16(b1, 0x32AEBA0 + 2 * i) for i in range(278)]
assert property_list[5] == 0x500D
assert property_list[102] == 0xD201
assert 0xD03C not in property_list
assert 0xD103 not in property_list
assert u16(b1, 0x3443048) == 0xD03C
assert u16(b1, 0x34432EC) == 0xD103

shutter_table = 0x32A9EF0
for shutter_8000_index in range(100):
    shutter_8000 = [b1.u32(shutter_table + 12 * shutter_8000_index + offset) for offset in (0, 4, 8)]
    if shutter_8000[1] == 0x7D00:
        break
else:
    raise AssertionError('1/8000 row not found')
assert shutter_8000[1] // 256 == 125

result = {
    'firmware': 'X-H2 5.30',
    'property_list': {'address': '0x32AEBA0', 'count': len(property_list)},
    'settings': [
        {
            'name': 'DRIVE MODE',
            'ui_setp': {'id': '0x858', 'name': 'UI_SETP_CONTINUOUS'},
            'usb_code': '0xD201',
            'usb_advertised': True,
            'values': {
                'S': {'ui_row': 0, 'ui_name': 'UI_CONTINUOUS_OFF', 'usb': '0x0004'},
                'CH_HIGH_SPEED_BURST': {'ui_row': 21, 'ui_name': 'UI_CONTINUOUS_ON_SPEED_H', 'usb': '0x0002'},
                'CL_LOW_SPEED_BURST': {'ui_row': 23, 'ui_name': 'UI_CONTINUOUS_ON_SPEED_L', 'usb': '0x0003'},
            },
            'proof': continuous,
            'note': 'The published dictionary maps only bracketing submodes to D201; the complete UI_SETP_CONTINUOUS table proves that D201 is the whole drive property.',
        },
        {
            'name': 'SHUTTER TYPE',
            'ui_setp': {'id': '0x827', 'name': 'UI_SETP_SHUTTER_TYPE'},
            'usb_code': '0xD03C',
            'usb_advertised': False,
            'values': {
                'MS': {'ui_row': 0, 'ui_name': 'UI_SHUTTER_TYPE_MECHA', 'usb': None},
                'ES': {'ui_row': 1, 'ui_name': 'UI_SHUTTER_TYPE_ELE', 'usb': None},
                'EF': {'ui_row': 2, 'ui_name': 'UI_SHUTTER_TYPE_SME', 'usb': None},
                'MS+ES': {'ui_row': 3, 'ui_name': 'UI_SHUTTER_TYPE_AUTO', 'usb': None},
                'EF+MS': {'ui_row': 4, 'ui_name': 'UI_SHUTTER_TYPE_SME_MECHA', 'usb': None},
                'EF+MS+ES': {'ui_row': 5, 'ui_name': 'UI_SHUTTER_TYPE_SME_MECHA_ELE', 'usb': None},
            },
            'proof': shutter_type,
            'note': 'D03C is named ShutterType by the X-T5 SDK plugin and occurs in the generic registry at 0x3443048, but is absent from the X-H2 5.30 PTP descriptor list and has no MOVZ handler in block1. USB values must not be invented; the owner must verify the menu.',
        },
        {
            'name': 'SHUTTER SPEED',
            'ui_setp': {'id': '0x89E', 'name': 'UI_SETP_SHUTTER_SPEED'},
            'usb_ui_setp': {'id': '0x991', 'name': 'UI_SETP_PC_EXPOSURETIME'},
            'usb_code': '0x500D',
            'usb_advertised': True,
            'values': {
                '1/8000': {'usb': '125', 'units': 'microseconds', 'datatype': 'UINT32'},
                '1/250': {'usb': '4000', 'units': 'microseconds', 'datatype': 'UINT32'},
            },
            'proof': {
                'descriptor_record': '0x32B6C14',
                'descriptor_ui_id': '0x991',
                'table': '0x32A9EF0',
                'row': shutter_8000,
                'scaled_value': '0x7D00 / 256 = 125',
                'descriptor_function': '0x2C02A0C',
            },
            'note': '0x500D is the advertised UINT32 exposure time in microseconds; the UI menu setting and its PTP bridge have separate UI_SETP numbers 0x89E and 0x991.',
        },
        {
            'name': 'IMAGE DISP / PreviewTime',
            'ui_setp': {'id': '0xB', 'name': 'UI_SETP_REC_VIEW'},
            'usb_code': '0xD103',
            'usb_advertised': False,
            'values': {
                'CONTINUOUS': {'ui_row': 0, 'ui_name': 'UI_REC_VIEW_PREVIEW', 'usb': '0xFFFF'},
                '0.5 SEC': {'ui_row': 2, 'ui_name': 'UI_REC_VIEW_S', 'usb': '0x0005'},
                '1.5 SEC': {'ui_row': 3, 'ui_name': 'UI_REC_VIEW_L', 'usb': '0x000F'},
                'OFF': {'ui_row': 5, 'ui_name': 'UI_REC_VIEW_OFF', 'usb': '0x0000'},
            },
            'proof': rec_view,
            'note': 'USB values come from official XAPIOpt.h SDK_PREVIEWTIME_* and match the fourth column of the UI_SETP_REC_VIEW table. D103 is absent from the X-H2 5.30 PTP descriptor list and occurs only in the generic registry at 0x34432EC.',
        },
    ],
    'sources': {
        'catalog': str(catalog_path),
        'official_xh2_header': 'https://github.com/Scdouglas1999/Fujicom/blob/main/Fuji/RequiredHeaders/X-H2.h',
        'official_sdk_values': 'https://github.com/Scdouglas1999/Fujicom/blob/main/Fuji/RequiredHeaders/XAPIOpt.h',
        'sdk_property_names': 'https://github.com/mikefsq/ptp/blob/main/fuji/names_xt5_gen.go',
        'published_dictionary': 'https://github.com/alexxpavloff6-ai/X-H2/blob/main/полные_отчёты/Чтение_камеры_по_USB/Словарь_значений.md',
    },
}

lines = []
for setting in result['settings']:
    ui = setting['ui_setp']
    lines.append(f"{setting['name']}: {ui['name']}={ui['id']} USB={setting['usb_code']} advertised={setting['usb_advertised']}")
    for name, value in setting['values'].items():
        lines.append(f"  {name}: row={value.get('ui_row')} {value.get('ui_name')} usb={value.get('usb')} {value.get('units', '')}")
    lines.append(f"  note: {setting['note']}")
(HERE / 'настройки.txt').write_text('\n'.join(lines) + '\n', encoding='utf-8')
(HERE / 'настройки.json').write_text(json.dumps(result, ensure_ascii=False, indent=2) + '\n', encoding='utf-8')
print('OK: settings and value tables verified; saved настройки.txt/.json')
