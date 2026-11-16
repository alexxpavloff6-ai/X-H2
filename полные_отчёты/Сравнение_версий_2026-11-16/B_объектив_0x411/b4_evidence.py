"""Сборка доказательства.json из результатов локализации (b1_sites.json),
VM-прогонов (vm_results.json) и зафиксированных вручную фактов.

Запуск:  python b1_locate.py --json ; python vm_focus.py --json ; python b4_evidence.py
Пишет доказательства.json (UTF-8) в этой папке.
"""
import json
import sys
from pathlib import Path

HERE = Path(__file__).resolve().parent
sys.path.insert(0, str(HERE.parent))

PATCH = {
    'X-H2': {
        'versions': ('5.30', '5.33'),
        'base_old': '0x29ae000', 'base_new': '0x29aa000',
        'main_ctor': ('0x2df0818', '0x2dec8a8'),
        'main_flag_cmp': (None, '0x2dec9b0'),
        'main_flag_store': (None, '0x2dec9b8 -> [sp,#0xb0] = request+0x50'),
        'sibling_ctor': ('0x2de9e5c', '0x2de5edc'),
        'sibling_flag': (None, '0x2de5f04-0x2de5f08 (cset w24) -> 0x2de601c (str w24,[sp,#0xb0])'),
        'dispatcher': ('0x2ceb0e4', '0x2ce70e4'),
        'mf_branch': ('0x2cecb34', '0x2ce8b34'),
        'mf_ops_old': 'op in {0x1e,0x20} (tst w0-0x1e,#0xfffffffd)',
        'mf_ops_new': 'op in {0x1e,0x20} (tst w0-0x1e,#0xfffffffd)',
        'old_step_prop': ('0x2cecd80 (prop_u8 0x1db3)', None),
        'old_value_prop': ('0x2cecd8c (prop_u16 0x1dba)', None),
        'new_const': (None, '0x2ce8b54 (out+0xa0=0xe4), 0x2ce8b60 (step=0x8c)'),
        'new_fallback': (None, '0x2ce8d80 (out+0xa0=0), 0x2ce8d88 (step=0x80)'),
        'flag_read': (None, '0x2ce8b4c-0x2ce8b50 (ldr [req+0x50]; cbz)'),
        'tail_out50': ('0x2cecca0-0x2cecca8', '0x2ce8ca0-0x2ce8ca8'),
        'helper': ('0x2f39820, 0x2f39878', '0x2f3458c (offset 0x58a58c)'),
        'status_consumer': ('0x2ce7c2c (bl 0x2ce7c50)', '0x2ce3c2c (bl 0x2ce3c50)'),
        'getters': ('u8 0x149b0cc, u16 0x149b18c', 'u8 0x14920fc, u16 0x14921bc'),
    },
    'X-H2S': {
        'versions': ('7.30', '7.31'),
        'base_old': '0x2cca000', 'base_new': '0x2cca000',
        'main_ctor': ('0x3107e50', '0x3107ee0'),
        'main_flag_cmp': (None, '0x3107fe8'),
        'main_flag_store': (None, '0x3107ff0 -> [sp,#0xb0]'),
        'sibling_ctor': ('0x310141c', '0x310149c'),
        'sibling_flag': (None, '0x31014c4 (cset w24)'),
        'dispatcher': ('0x3002ee0', '0x3002ee0'),
        'mf_branch': ('0x3004458', '0x3004458'),
        'mf_ops_old': 'op in {0x1b,0x1d,0x1f,0x21,0x23} (маска 0x0000000AA8000000)',
        'mf_ops_new': 'op in {0x1b,0x1d,0x1f,0x21,0x23} (маска 0x0000000AA8000000)',
        'old_step_prop': ('0x3004478 (prop_u8 0x1db3)', None),
        'old_value_prop': ('0x3004484 (prop_u16 0x1dba)', None),
        'new_const': (None, '0x3004484 (out+0xa0=0xe4), 0x3004490 (step=0x8c)'),
        'new_fallback': (None, '0x30046b0 (out+0xa0=0), 0x30046b8 (step=0x80)'),
        'flag_read': (None, '0x300447c-0x3004480'),
        'tail_out50': ('0x3004494', '0x30045d0'),
        'helper': ('0x32505b4, 0x3250604', '0x324f340, 0x324f350'),
        'status_consumer': (None, None),
        'getters': ('u8 0x17bac60, u16 0x17bad20', 'u8 0x17bac68, u16 0x17bad28'),
    },
    'X-T5': {
        'versions': ('4.31', '4.32'),
        'base_old': '0x28eb000', 'base_new': '0x28eb000',
        'main_ctor': ('0x2d2dea4', '0x2d2df44'),
        'main_flag_cmp': (None, '0x2d2e04c'),
        'main_flag_store': (None, '0x2d2e054 -> [sp,#0xb0]'),
        'sibling_ctor': ('0x2d274e8', '0x2d27578'),
        'sibling_flag': (None, '0x2d275a0 (cset w24)'),
        'dispatcher': ('0x2c29da8', '0x2c29da8'),
        'mf_branch': ('0x2c2b7f8', '0x2c2b7f8'),
        'mf_ops_old': 'op in {0x1e,0x20}',
        'mf_ops_new': 'op in {0x1e,0x20}',
        'old_step_prop': ('0x2c2ba44 (prop_u8 0x1db3)', None),
        'old_value_prop': ('0x2c2ba50 (prop_u16 0x1dba)', None),
        'new_const': (None, 'НЕ константы: flag=1 -> props 0x205a/0x205e (0x2c2b818), '
                            'flag=0 -> props 0x2059/0x205c (0x2c2ba50)'),
        'new_fallback': (None, 'см. new_const'),
        'flag_read': (None, '0x2c2b810-0x2c2b814'),
        'tail_out50': ('0x2c2b964', '0x2c2b970'),
        'helper': ('0x2e74b38, 0x2e74b88', '0x2e738e4, 0x2e738f4'),
        'status_consumer': (None, None),
        'getters': ('u8 0x149519c, u16 0x149525c', 'u8 0x14951a4, u16 0x1495264'),
    },
}

FACTS = [
    dict(id='N1', level='доказано (отрицательный)',
         claim='В прошивке нет таблицы названий объективов и нет строк EXIF LensModel: '
               '"XF30mm", "30mm", "XF30", "F2.8", "LensModel" не найдены ни в одном из '
               '4 блоков (X-H2 5.33) и в сыром FWUP0028 (2).DAT (0x6931550 байт). '
               'Единственные 3 вхождения "Macro" — в блоке 0, к объективам не относятся.',
         refs=['scan.py / поиск по blocks/*.bin и DAT']),
    dict(id='D1', level='доказано',
         claim='0x411 — уже существовавший модельный ID: в старой прошивке X-H2 '
               'сравнение с 0x411 встречается 15 раз в блоке 1 (+4 в блоке 0), в новой — 17 '
               '(добавлены ровно те два, что в конструкторах). Значит 0x411 не введён этим патчем.',
         refs=['b1_locate.py', 'b1_sites.json', 'cmp411 в 0x2df124c (old X-H2, не изменено)']),
    dict(id='D2', level='доказано',
         claim='Патч добавляет в оба конструктора запроса флаг request+0x50 = (lensID==0x411): '
               'X-H2 0x2dec9b0-0x2dec9b8 и 0x2de5f04/0x2de601c; X-H2S 0x3107fe8-0x3107ff0 и '
               '0x31014c4; X-T5 0x2d2e04c-0x2d2e054 и 0x2d275a0. Из-за нового поля размер '
               'запроса вырос 0x60 -> 0x68 (в main-конструкторе база запроса сдвинулась '
               'sp+0x68 -> sp+0x60).',
         refs=['b2_windows.txt: H2 main old/new, H2S main old/new, T5 main old/new']),
    dict(id='D3', level='доказано',
         claim='Диспетчер lens-запроса для MF-операций в old брал пару (шаг, значение) из '
               'свойств 0x1db3 (u8) и 0x1dba (u16) и писал out+0x50 = 2*шаг, out+0xa0 = значение. '
               'В new для lens==0x411 подставляются 0x8c/0xe4, иначе 0x80/0 => out+0x50 = 0x118 '
               'или 0x100, out+0xa0 = 0xe4 или 0.',
         refs=['H2 0x2cecd80/0x2cecd8c -> 0x2ce8b54/0x2ce8b60 + 0x2ce8d80',
               'H2S 0x3004478/0x3004484 -> 0x3004484/0x3004490 + 0x30046b0',
               'VM1/VM2 в vm_results.json']),
    dict(id='D4', level='доказано (различие моделей)',
         claim='X-T5 реализован иначе: вместо констант читаются свойства 0x205a/0x205e при '
               'флаге и 0x2059/0x205c без флага (0x2c2b818 и 0x2c2ba50). VM: при всех '
               'свойствах=0 X-T5 даёт (0,0), а X-H2/X-H2S — (0xe4,0x118), т.е. константы.',
         refs=['VM1 X-T5 "свойства=0"', 'b2_windows.txt: T5 disp new']),
    dict(id='D5', level='доказано',
         claim='Набор MF-операций: X-H2 и X-T5 — {0x1e,0x20} (sub #0x1e + tst #0xfffffffd); '
               'X-H2S — {0x1b,0x1d,0x1f,0x21,0x23} (битовая маска 0x0000000AA8000000, '
               '0x3004460-0x3004474). VM подтверждает: у X-H2S op=0x1f идёт по MF-ветке, '
               'а op=0x1e — по «свойствам по умолчанию».',
         refs=['VM1/VM2 X-H2S', 'b2_windows.txt: H2S disp']),
    dict(id='D6', level='доказано',
         claim='Потребители out+0x50 / out+0xa0: (a) sibling-конструктор копирует out+0x50 в '
               'свой dest+0x448+0x20 (X-H2 new 0x2de6138-0x2de613c) и не читает out+0xa0; '
               '(b) вызывающий 0x2ce3c2c копирует out+0x50 -> dest+0x28 и out+0xa0 -> dest+0x8c; '
               'его единственный вызывающий 0x2f60ce0 передаёт dest = 0x4bd52d0, значит '
               'out+0xa0 попадает в глобал 0x4bd535c; (c) main-конструктор копирует только '
               'out+0x54 -> dest+0xd0, out+0x50/out+0xa0 не копирует.',
         refs=['b2_windows.txt: H2 status caller new, H2 sibling dest new']),
    dict(id='D7', level='доказано',
         claim='Глобал 0x4bd535c (куда ложится out+0xa0) в другом месте пишется как '
               'prop_u16(0x1db8) (0x2f3bf80-0x2f3bf8c) и читается в 0x2f462c4, откуда значение '
               'передаётся объекту 0x4b0b148 (вызов 0x2f359f0). То есть out+0xa0 — величина '
               'того же рода, что «значение» из семейства 0x1db8/0x1dba.',
         refs=['b2_windows.txt: H2 1db8->global, H2 global reader']),
    dict(id='D8', level='доказано',
         claim='Семейство свойств: пары (u8 шаг, u16 значение) — 0x1db2/0x1db8, 0x1db3/0x1dba, '
               '0x1db4/0x1dbc, 0x1db5/0x1dbe, 0x1db6/0x1dc0, 0x1db7/0x1dc2. Пара выбирается по '
               'классу операции (таблица op->class 0x33b0370, классы 1/2 -> 0x1db5/0x1dbe, '
               '4 -> 0x1db6/0x1dc0, request+0x28==0x10 -> 0x1db7/0x1dc2, иначе 0x1db4/0x1dbc), '
               'а для MF-операций — 0x1db3/0x1dba.',
         refs=['H2 new 0x2ce8c74-0x2ce8df4', 'старые 0x2cecc74-0x2cecddc']),
    dict(id='D9', level='доказано',
         claim='Новый helper 0x2f3458c (X-H2 new, смещение блока 1 = 0x58a58c; X-H2S '
               '0x324f340; X-T5 0x2e738e4) заменил старые обёртки 0x2f39820/0x2f39878, которые '
               'для «lens-kind 3..5» читали 0x1dba, а иначе 0x1db8. Новый helper 0x1dba не '
               'читает: выбирает 0x1db8 либо 0x205c/0x205e по трём аргументам.',
         refs=['b2_windows.txt: H2 helper old A/B, H2 helper new']),
    dict(id='D10', level='доказано (отрицательный)',
         claim='Проверка request+0x25 к патчу не относится: число инструкций ldrb [x,#0x25] '
               'одинаково в old и new (X-H2 23/23, X-H2S 23/23, X-T5 24/24), ни одной новой; '
               'ни диспетчер, ни оба конструктора request+0x25 не читают.',
         refs=['b1_locate.py/scan по 0x39400000+imm12=0x25']),
    dict(id='I1', level='сильный кандидат',
         claim='Смысл чисел: out+0x50 — «шаг» в полушагах (поле = 2 x свойство): 0x100=256 для '
               'обычных объективов, 0x118=280 для 0x411; out+0xa0 — «значение/диапазон» из той '
               'же пары: 0 для обычных, 0xe4=228 для 0x411. Это параметры пересчёта поворота '
               'кольца в перемещение фокуса, а не угол в градусах: углы задаются отдельно '
               '(UI_MF_ANGLE_090/180/270/360DEG), и 228/280 не соответствуют им и не кратны 90.',
         refs=['D3', 'строки UI_MF_ANGLE_* (блок 1 X-H2 new 0x31ba208)']),
    dict(id='I2', level='сильный кандидат',
         claim='Почему старая логика ломала MF на 0x411: пара (0x1db3,0x1dba) для этого '
               'объектива содержала неподходящие значения (в пределе — нули), из-за чего '
               'MF-команда получала out+0x50=0. VM-2 показывает: при свойствах=0 старая '
               'прошивка даёт (out+0x50=0, out+0xa0=0), а при 140/228 — ровно новые (0x118,0xe4).',
         refs=['VM2 все модели', 'D3']),
    dict(id='G1', level='гипотеза (внешний факт)',
         claim='0x411 = XF30mmF2.8 R LM WR Macro. Внутри прошивки имени нет (N1); '
               'подтверждается только тем, что ID существовал до патча (D1), специально '
               'обрабатывается именно в MF-пути (D2-D3) и не попадает ни в один бит-класс '
               '0x1000/0x2000/0x4000/0x8000 (класс 0). Формально это факт из релиз-нот '
               'Fujifilm, а не из DAT.',
         refs=['N1', 'D1', 'D2']),
    dict(id='G2', level='гипотеза',
         claim='Функции 0x2dceb54 и 0x2ddd28c (X-H2 new) заполняют запись с lens-полями и '
               'специально ветвятся по 0x411 (0x2dcec04, 0x2ddd368/0x2ddd374) — вероятно, '
               'это запись lens-данных для файла/протокола (maker-note/PTP). Точное '
               'назначение записи не доказано.',
         refs=['0x2dceb54, 0x2ddd28c']),
]

NEGATIVES = [
    'Таблицы названий объективов / EXIF LensModel в прошивке нет (N1) — доказать имя по строкам нельзя.',
    'Нет таблицы «ID -> фокусное/диафрагма»: поиск 0x411 рядом с 30 (0x1e) в данных дал только случайные совпадения (5 адресов, все вне таблиц).',
    'helper 0x58a58c не связан с 0x411: он не проверяет этот ID и не пишет out+0x50/out+0xa0.',
    'Проверка request+0x25 не добавлена и не изменена (D10).',
    'Патч НЕ одинаков во всех трёх моделях: X-T5 использует свойства 0x2059/0x205a/0x205c/0x205e, а X-H2/X-H2S — константы (D4).',
    'Версия «228/280 — угол поворота кольца в градусах» не подтверждается: UI-углы 90/180/270/360, а поле = 2 x свойство.',
]

OPEN = [
    'Что физически означают 228 и 280 (импульсы на оборот? позиция лимита? передаточное число?) — '
    'нужна трассировка до транспорта объектива (после объекта 0x4b0b148 / dest+0x448).',
    'Кто и когда пишет свойства 0x1db3/0x1dba в old (setter не найден: только чтения; вероятно, '
    'значения приходят из блока lens-данных, обновляемого по протоколу).',
    'Полный список моделей, для которых срабатывает MF-ветка в X-H2S (операции 0x1b/0x1d/0x1f/0x21/0x23).',
]


def main():
    sites = json.loads((HERE / 'b1_sites.json').read_text(encoding='utf8')) \
        if (HERE / 'b1_sites.json').exists() else {}
    vm = json.loads((HERE / 'vm_results.json').read_text(encoding='utf8')) \
        if (HERE / 'vm_results.json').exists() else {}
    data = {
        'meta': {
            'task': 'B: XF30mm Macro — подтвердить lens ID 0x411 и восстановить цепь до фокусировки',
            'dates': '2026-11-16',
            'method': 'статический анализ ARM64 (capstone) + Unicorn; только чтение blocks/*.bin',
            'scripts': ['scan.py', 'b1_locate.py', 'b2_windows.py', 'vm_focus.py', 'b4_evidence.py'],
            'outputs': ['отчёт.md', 'b1_sites.json', 'b2_windows.txt', 'vm_results.json',
                        'доказательства.json'],
            'fwcommon': '../fwcommon.py (не изменялся)',
        },
        'patch_sites': PATCH,
        'locator': sites,
        'vm': vm,
        'facts': FACTS,
        'refuted': NEGATIVES,
        'open_questions': OPEN,
    }
    (HERE / 'доказательства.json').write_text(
        json.dumps(data, indent=1, ensure_ascii=False), encoding='utf8')
    print('saved доказательства.json: facts=%d, refuted=%d, open=%d' % (
        len(FACTS), len(NEGATIVES), len(OPEN)))


if __name__ == '__main__':
    main()
