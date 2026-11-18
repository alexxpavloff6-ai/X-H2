import json
import struct
import sys
from pathlib import Path

sys.path.insert(0, r'<корень проекта>\Анализ_прошивки\Сравнение_версий_2026-11-16')
from fwcommon import load, adrp_refs, bl_callers

out = Path(__file__).resolve().parent
ids = [0x8C0, 0x6FB, 0x618, 0x61C, 0x620, 0x70D, *range(0x710, 0x724), 0x1E2]
b0 = load('X-H2', 'old', 0)
b1 = load('X-H2', 'old', 1)
b2 = load('X-H2', 'old', 2)

def u16s(block, address, count):
    off = block.off(address)
    return [struct.unpack_from('<H', block.data, off + 2*i)[0] for i in range(count)]

def callers(block, target):
    return [hex(site) for site, _ in bl_callers(block, target)]

result = {
  'title': 'Путь настроек автофокуса к рабочим структурам X-H2 5.30',
  'date': '2026-11-18',
  'firmware': 'Fujifilm X-H2 5.30',
  'camera_used': False,
  'scope': {'blocks': [0, 1, 2], 'runtime_bases': [hex(b0.base), hex(b1.base), hex(b2.base)]},
  'setting_ids': [hex(x) for x in ids],
  'findings': [
    {'id': 'AF-copy-01', 'level': 'Д', 'source': 'block 1, 0x2bd5114–0x2bd5xxx', 'claim': 'Функция отдельными вызовами читает ряд UI_SETP и копирует значения через 0x11335c4 в производные поля, в том числе 0x618→0xACD, 0x624→0xAE0, 0x620→0xADF, с индексами 0/1. Это ручная передача отдельных параметров, не проход по таблице AF-id.'},
    {'id': 'AF-copy-02', 'level': 'Д', 'source': 'block 1, 0x2bf8784–0x2bf8838; 0x2bf8848–0x2bf88e0', 'claim': 'Функции читают выбранные TARGET_* значения (0x715/0x71C/0x723 и 0x716/0x71D), преобразуют через 0x1135930 и собирают строку с 0x2bf51cc; результат передают 0x2bf6704. Это путь формирования/передачи параметров, не доказанное чтение алгоритмом фокусировки.'},
    {'id': 'AF-state-01', 'level': 'Д', 'source': 'block 1, 0x2c99ee4/0x2c99f04/0x2c99f24', 'claim': 'Поля 0x2680474/478/47C читаются только этими тремя соседними инструкциями, каждая из которых находится в ветви общего геттера и переводит значение для ответа. В блоках 0–2 иных прямых ссылок на эти поля не найдено.'},
    {'id': 'AF-state-02', 'level': 'Г', 'source': '0x3bcab48, 0x3bc0000–0x3bd0000, 0x4b8d230', 'claim': 'Не установлена цепь записи AF-настроек в долгоживущие структуры. Для 0x3bcab48 и его страницы статические ADRP-ссылки в блоках 0–2 не найдены. Прямые ссылки на 0x4b8d230 относятся к общей структуре со сбросами полей +0x664/+0x668 и +0x434/+0x438, но связи с запрошенными AF-id нет.'},
    {'id': 'AF-mode-01', 'level': 'Д', 'source': 'block 0, 0x1141ee0', 'claim': '0x1141ee0 разрешает целочисленный код режима в одну из ветвей/именованных значений MODE_RECORD. Прямого вызова этой функции из блока 1 не найдено; сам резолвер не показывает запись AF-настроек.'},
    {'id': 'AF-batch-01', 'level': 'Д', 'source': 'block 0, 0x18bb198/0x18bb2b8; 0x12e6910; 0x132e3f4/0x132f088', 'claim': 'В таблицах по 0x18bb198/0x18bb2b8 есть записи UI_SETP с ID 0x70D и TARGET_*. Проверенные циклы 0x12e6910 и 0x132e3f4 используют другие таблицы (0x18bbcf0 и 0x18bbbc0) с кодами групп 0–0x1A/0–0xA, а не список AF-id; связь этих ID-таблиц с пакетным чтением AF не доказана.'},
    {'id': 'AF-batch-02', 'level': 'Г', 'source': 'block 0, 0x17529d8; block 2, 0x442320', 'claim': 'Найдены последовательности u16/u32 с несколькими AF-id. Для 0x17529d8 не подтверждён код, проходящий именно по этой последовательности и вызывающий общий геттер/доступ к банку; 0x442320 находится в блоке 2 без найденных прямых ссылок на начало. Одного совпадения чисел недостаточно, чтобы назвать их рабочим снимком.'},
    {'id': 'AF-boundary-01', 'level': 'Г', 'source': 'block 1 and encrypted block boundary', 'claim': 'Алгоритм вычисления фокуса не найден в разобранных блоках 0–2. Если следующий потребитель находится в зашифрованной области 0x2300274–0x2476DAB, другом процессоре или за сообщениями между задачами, статической цепи на этом месте нет.'}
  ],
  'arrays': [
    {'address': '0x17529d8', 'block': 0, 'element_type': 'u16 LE', 'count': 24, 'values': [hex(x) for x in u16s(b0,0x17529d8,24)], 'interpretation': 'AF-id есть вместе, но xref к точному началу и проход, вызывающий геттер для элементов, не подтверждены.'},
    {'address': '0x18bb198', 'block': 0, 'element_type': 'descriptor records', 'sample_ids': [hex(struct.unpack_from('<I',b0.data,b0.off(0x18bb198+i*0x10))[0]) for i in range(12)] + [hex(struct.unpack_from('<I',b0.data,b0.off(0x18bb2b8+i*0x10))[0]) for i in range(12)], 'stride': '0x10', 'interpretation': 'Таблицы дескрипторов содержат последовательности 0x70D–0x717 и 0x718–0x723. Проверенные циклы 0x12e6910/0x132e3f4 адресуют другие таблицы, а читатель именно этих записей не сопоставлен с пакетным получением значений.'},
    {'address': '0x442320', 'block': 2, 'element_type': 'mixed records / u16 IDs within 64-byte window', 'count': 12, 'values': [hex(x) for x in [0x710,0x711,0x712,0x713,0x714,0x715,0x716,0x717,0x718,0x719,0x71a,0x71b]], 'interpretation': 'В пределах 64 байт обнаружены ID 0x710–0x71B, но они не лежат плотным массивом; прямые ссылки к началу не найдены.'}
  ],
  'structure_checks': {
    'generic_getter_calls': {f'block_{i}': len(bl_callers(b,0x2c93fd4)) for i,b in [(0,b0),(1,b1),(2,b2)]},
    'mode_resolver_block1_call_sites': callers(b1,0x1141ee0),
    'global_af_fields': {'0x2680474': adrp_refs(b1,0x2680474), '0x2680478': adrp_refs(b1,0x2680478), '0x268047c': adrp_refs(b1,0x268047c)},
    'shooting_structure_pointer_page_sites': {'0x3bcab48': [hex(site) for site,_ in __import__('fwcommon').adrp_sites(b1,0x3bcab48)]},
    'callers_of_known_helpers': {'0x12aa788_block1': callers(b1,0x12aa788), '0x113a668_block1': callers(b1,0x113a668)}
  },
  'limitations': [
    'Отсутствие прямой ссылки не исключает вычисление адреса, вызов через таблицу, передачу указателя из другого блока или путь во время исполнения.',
    'Названия задач и алгоритмическое назначение не выводились только из близости строки или ID.',
    'Камера и прошивка не изменялись.'
  ]
}
(out/'результат.json').write_text(json.dumps(result, ensure_ascii=False, indent=2) + '\n', encoding='utf-8')
print(out/'результат.json')


