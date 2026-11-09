"""Наглядная схема по проверенным данным; никакой код прошивки не исполняется."""
from pathlib import Path
import json
from PIL import Image, ImageDraw, ImageFont

HERE = Path(__file__).resolve().parent
proof = json.loads((HERE/'Проверка_границы_систем.json').read_text(encoding='utf-8'))
assert proof['unique_verified_task_ids'] == 150
W, H = 1880, 1520
im = Image.new('RGB', (W, H), '#F5F3EE')
d = ImageDraw.Draw(im)
fonts = {}


def font(size, bold=False):
    key = size, bold
    if key not in fonts:
        fonts[key] = ImageFont.truetype('C:/Windows/Fonts/segoeuib.ttf' if bold else 'C:/Windows/Fonts/segoeui.ttf', size)
    return fonts[key]


def txt(x, y, text, size=30, color='#263D46', bold=False):
    d.text((x, y), text, font=font(size, bold), fill=color)


def box(rect, fill, outline=None, radius=22):
    d.rounded_rectangle(rect, radius=radius, fill=fill, outline=outline, width=2)


def arrow(points, color='#4A6C70', width=5, both=False):
    d.line(points, fill=color, width=width, joint='curve')
    import math
    def head(a, b):
        angle = math.atan2(b[1]-a[1], b[0]-a[0])
        length, half = 18, 10
        base = b[0]-length*math.cos(angle), b[1]-length*math.sin(angle)
        d.polygon([b, (base[0]+half*math.sin(angle), base[1]-half*math.cos(angle)),
                   (base[0]-half*math.sin(angle), base[1]+half*math.cos(angle))], fill=color)
    head(points[-2], points[-1])
    if both:
        head(points[1], points[0])


txt(64, 42, 'Как разделена работа в X-H2', 58, bold=True)
txt(66, 122, 'По коду FWUP0028.DAT 5.30  ·  проверка 01.11.2026', 29, '#647578')

box((60, 195, 824, 792), '#E2EDE8')
box((1056, 195, 1820, 792), '#E3EAF4')
txt(92, 216, 'ThreadX', 48, '#21584B', True)
txt(92, 278, 'Основная программа камеры', 32, '#21584B', True)
left = [
    ('Меню и экран', 'ui · touchPanel · graphic · lcdevf'),
    ('Фото и видео', 'reccont · recmv · recb… · rmb…'),
    ('Фокусировка и объектив', 'paf · directaf · chase · lenscom'),
    ('Подготовка изображения', 'calc · imgdc · movdc'),
    ('Файлы и управление передачей', 'filecont1…3 · ftp_cont · networkPcsh'),
]
for n, (a, b) in enumerate(left):
    y = 346+n*84
    txt(92, y, a, 31, bold=True)
    txt(92, y+40, b, 27, '#4A655F')

txt(1088, 216, 'Linux', 48, '#345781', True)
txt(1088, 278, 'Сетевые и служебные программы', 32, '#345781', True)
right = [
    ('Запросы от основной программы', 'rpmsg-daemon'),
    ('Сетевые операции и Wi-Fi', 'socket · connect · send · recv'),
    ('Передача файлов', 'ff_ftp · ff_frameio'),
    ('Вспомогательные файловые операции', 'isgc_futil_daemon'),
    ('Отдельные дополнительные службы', 'ff_c2pa · ff_crypto: состав найден'),
]
for n, (a, b) in enumerate(right):
    y = 346+n*84
    txt(1088, y, a, 29 if n==3 else 31, bold=True)
    txt(1088, y+40, b, 27, '#536B88')

arrow([(838, 480), (1042, 480)], both=True)
txt(874, 382, 'RPmsg', 32, bold=True)
txt(853, 430, 'запрос', 25)
txt(867, 503, 'ответ', 25)
txt(853, 552, 'Общая', 25)
txt(853, 585, 'память', 25)

arrow([(442, 806), (442, 861)])
box((60, 866, 1820, 1060), '#FFFDFC', '#C8D0CB')
txt(92, 886, 'Аппаратные обработчики и устройства', 35, bold=True)
txt(92, 940, 'Программа готовит задание; устройство применяет его к данным или управляет механизмом.', 29)
txt(92, 984, 'Цвет: проверены записи в 0xFF96C634 / 0xFF96C638. Внутренняя формула блока ещё не восстановлена.', 27)

txt(64, 1094, 'Назначения ядер, найденные в программе', 38, bold=True)
cards = [
    ('Ядро 0', 'ThreadX', ['Меню, съёмка,', 'файлы, управление'], '#E2EDE8'),
    ('Ядро 1', 'ThreadX', ['Расчёты, изображение,', 'часть распознавания'], '#E2EDE8'),
    ('Ядро 2', 'Переход к Linux', ['Маска 0x4 = 0100', 'maxcpus=1'], '#E3EAF4'),
    ('Ядро 3', 'ThreadX', ['Фокусировка, объектив,', 'другие задачи'], '#E2EDE8'),
]
for n, (a, b, lines, fill) in enumerate(cards):
    x = 60+n*446
    box((x, 1160, x+422, 1370), fill)
    txt(x+24, 1176, a, 34, bold=True)
    txt(x+24, 1223, b, 29, bold=True)
    txt(x+24, 1274, lines[0], 26)
    txt(x+24, 1312, lines[1], 26)
txt(65, 1394, 'Это программные назначения, а не измерение нагрузки. В ThreadX есть также служебная задача idle2.', 26)
txt(65, 1432, 'Проверены 151 запись создания / 150 номеров задач. Это не список всех одновременно работающих задач.', 26)
txt(65, 1470, 'Назначения отдельных задач и аппаратных алгоритмов исследованы не полностью.', 24, '#647578')

out = HERE/'Кто_за_что_отвечает_XH2.png'
im.save(out)
print(out)
