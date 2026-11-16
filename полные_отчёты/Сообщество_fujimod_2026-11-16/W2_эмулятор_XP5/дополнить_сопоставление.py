"""Дополнить сопоставление.json выводами по companion Cortex-M4 (только чтение DAT)."""
from pathlib import Path
import json

HERE = Path(__file__).resolve().parent
p = HERE / 'сопоставление.json'
j = json.loads(p.read_text(encoding='utf8'))

j['проверки'] += [
    {
        'что': 'отображение flash↔DAT (DAT = flash + 0x274, XOR 0xFF)',
        'наш': 'inverted(DAT)[0x60274:0x68274]',
        'fujimod': 'catalog/firmware/xt5/4.31/flash.generated.json control {offset:0x60000, size:0x8000, sha256:3867c1a8…}; xh2s/7.30: 886e711e…',
        'итог': 'SHA совпали на обеих моделях',
        'уровень': 'Д',
    },
    {
        'что': 'таблица компонентных дескрипторов (прелоад 0x10C0000)',
        'наш': 'DAT 0x1A0274, SHA 8fbd84f3dbe3ab4ad5a468f40611827e1bab7030827f610c6929bdb96a4933c2 (X-T5)',
        'fujimod': 'data/xt5-431/manifest.toml:26–31 preload 0x10C0000 из DAT 0x1A0274, тот же SHA',
        'итог': 'совпало',
        'уровень': 'Д',
    },
    {
        'что': 'записи таблицы id=0/4/5 против streams.json и наших блоков',
        'наш': 'X-H2 b0 0x1101000, b1 0x29AE000; loader 0x40000',
        'fujimod': 'дескрипторы id=4 (0x1101000, flash 0x300000), id=5 (0x29AE000, flash 0x840000), id=0 (0x40000, flash 0x60000)',
        'итог': 'адреса, flash-смещения и размер id=5 (0xECC000 = 15 515 648) совпали',
        'уровень': 'Д',
    },
    {
        'что': 'образ M4 по дескриптору id=3',
        'наш': 'DAT 0x1C0274, 0x31A80 Б, SHA 85d29ade613aa01c… (X-H2 5.30 и 5.33)',
        'fujimod': 'manifest X-T5 «flash f01c0000 перед reset release»; X100VI «section5 … SRAM 0xFA200000»',
        'итог': 'образ найден, сигнатура векторов и литералы mailbox подтверждают Cortex-M4',
        'уровень': 'Д',
    },
    {
        'что': 'сигнатура векторов M4 в наших четырёх FFLZ-блоках',
        'наш': '00 0a 00 00 01 0a 00 00 dd 18 00 00 35 0a 00 00 …',
        'fujimod': '—',
        'итог': 'отсутствует во всех блоках X-H2/X-H2S/X-T5: M4 не входит в FFLZ-блоки',
        'уровень': 'Д',
    },
    {
        'что': 'неизменность образа M4 между версиями',
        'наш': 'X-H2 5.30 = 5.33, X-T5 4.31 = 4.32, X-H2S 7.30 = 7.31 (SHA равны)',
        'fujimod': '—',
        'итог': 'companion-прошивка в этих обновлениях не менялась',
        'уровень': 'Д',
    },
]

j['companion_M4_сопоставление'] = [
    {
        'id': 31,
        'вопрос': 'Откуда companion Cortex-M4 берёт свой код?',
        'вывод': 'код копируется A53 из flash 0x1C0000 в SRAM 0xFA200000',
        'fujimod': 'X-T5: «stock 13f7b58 копирует flash f01c0000 в SRAM перед reset release»; X100VI: «A53 14d3f14 копирует/зануляет Section5»',
        'уровень': 'Д',
        'ссылка': 'crates/emulator-xp5-bringup/data/xt5-431/manifest.toml:21–24; .../x100vi-131/manifest.d/60-mcore.toml:1–3',
    },
    {
        'id': 32,
        'вопрос': 'Есть ли образ M4 внутри DAT?',
        'вывод': 'да: DAT 0x1C0274, длина 0x31A80, raw без сжатия, вне FFLZ-блоков',
        'fujimod': 'адрес flash 0x1C0000 (X-T5) + наша таблица компонентных дескрипторов (id=3)',
        'уровень': 'Д',
        'ссылка': 'companion_M4.md §2, §5; companion_M4_вывод.txt',
    },
    {
        'id': 33,
        'вопрос': 'Это «пятый FFLZ-блок»?',
        'вывод': 'нет: образ не имеет FFLZ-заголовка и адресуется таблицей компонентов по flash 0x1A0000',
        'fujimod': 'таблица компонентных дескрипторов (запись id=3) — аналог их «section5»',
        'уровень': 'Д',
        'ссылка': 'companion_M4.md §2, §5',
    },
    {
        'id': 34,
        'вопрос': 'Размер образа и BSS',
        'вывод': 'X-H2 0x31A80 + BSS 0x19340; X-T5 0x32470 + 0x193C0; X-H2S 0x22900 + 0x167E4; SRAM 0xFA200000, vector_base 0',
        'fujimod': 'SRAM 1 МиБ по 0xFA200000, vector_base 0 (soc.json companion)',
        'уровень': 'Д',
        'ссылка': 'catalog/soc/xp5/soc.json:58–64, 1001–1013; companion_M4.md §2',
    },
    {
        'id': 35,
        'вопрос': 'Формат образа: архитектура, карта памяти, reset',
        'вывод': 'ARMv7-M Thumb: SP=0xA00, reset=0xA01, 179 IRQ-векторов, CCR 0xE000ED14=0x210, SHCSR=0; локальный 0 = SRAM, периферия через +0x60000000',
        'fujimod': 'M-profile Cortex-M4 (Unicorn), vector_base 0, clock 600 МГц; mailbox локально 0x5F90E100',
        'уровень': 'Д',
        'ссылка': 'crates/emulator-boot/src/graph.rs:301–341; catalog/soc/xp5/soc.json:1001–1013; companion_M4.md §3',
    },
    {
        'id': 36,
        'вопрос': 'Где A53 берёт адрес/размер образа M4?',
        'вывод': 'дескриптор id=3 в таблице по flash 0x1A0000 (DAT 0x1A0274): +0x10 size, +0x20 bss, +0x28 flash; геттер 0x14E1BB0',
        'fujimod': '«Cold component descriptor table read through reset 0x2fa4», прелоад 0x10C0000 из DAT 0x1A0274',
        'уровень': 'Д',
        'ссылка': 'crates/emulator-xp5-bringup/data/xt5-431/manifest.toml:26–31; companion_M4.md §2',
    },
    {
        'id': 37,
        'вопрос': 'Как и когда A53 запускает M4?',
        'вывод': 'холодный старт: если бит 21 регистра 0xFF90C928 = 0 → GPIO 9.8/9.9, копия, BSS, mailbox=0, cause=0x7F, затем SET бит 21',
        'fujimod': 'mailbox 0xFF90E100 (8 слов + cause W1C); «before reset release»',
        'уровень': 'Д для последовательности, К для смысла GPIO',
        'ссылка': 'crates/emulator-xp5-io/src/mailbox.rs:70–120; companion_M4.md §4',
    },
    {
        'id': 38,
        'вопрос': 'Кто инициатор mailbox?',
        'вывод': 'A53: обнуляет payload и пишет 0x7F в cause до спуска M4; далее M4 пишет reply/status/fault (INTID 141/142/143)',
        'fujimod': 'модель mailbox: cause 0/3 → M4 INTID 55/58, 4/5/6 → A53 141/142/143; payload непрозрачен',
        'уровень': 'Д для порядка, К для семантики битов',
        'ссылка': 'crates/emulator-xp5-io/src/mailbox.rs:1–4, 70–120',
    },
    {
        'id': 39,
        'вопрос': 'Карта памяти M4 (flash/SRAM/периферия)',
        'вывод': 'своего flash нет; local 0..0xFFFFF = SRAM 0xFA200000; local = phys + 0x60000000 (mod 2^32) для периферии и DRAM-окон companion-map-1/2',
        'fujimod': 'companion-map-0/1/2, vector_base 0, companion-sram 0xFA200000 1 МиБ',
        'уровень': 'Д',
        'ссылка': 'catalog/soc/xp5/soc.json:58–64, 605–640',
    },
    {
        'id': 40,
        'вопрос': 'Где образ M4 у X100VI?',
        'вывод': 'не локализован: у X100VI другая таблица (flash 0x40000/0x40800, DAT 0x6402BC/0x1202BC), записи id=3 нет',
        'fujimod': 'A53 0x14D3F14 копирует section5, но flash-смещение не зафиксировано',
        'уровень': 'не найдено',
        'ссылка': 'companion_M4.md §7',
    },
]

j['покрытие_пунктов']['6_companion_M4'] = (
    'companion_M4.md; companion_M4.py; companion_M4_вывод.txt: '
    'таблица компонентных дескрипторов (DAT 0x1A0274), образ M4 (DAT 0x1C0274, 0x31A80), '
    'A53 0x13FB194, release бит 21 0xFF90C928, mailbox 0xFF90E100'
)

p.write_text(json.dumps(j, ensure_ascii=False, indent=2), encoding='utf8')
print('OK: проверок', len(j['проверки']), 'сопоставлений', len(j['сопоставление']),
      'companion', len(j['companion_M4_сопоставление']))
