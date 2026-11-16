# -*- coding: utf-8 -*-
"""Шаг 20: сборка доказательства.json — все проверяемые факты с адресами.

Запуск: python a20_evidence.py   (самодостаточно, читает только DAT-блоки)
"""
import sys, os, json, struct
sys.path.insert(0, r'<корень проекта>\Анализ_прошивки\Сравнение_версий_2026-11-16')
from fwcommon import *  # noqa
from fwemu import scan_address
import fwcommon
import a19_vm_stride as vm

HERE = os.path.dirname(os.path.abspath(__file__))

META = {
    ('X-H2', 'old'): dict(version='5.30', dat=r'<корень проекта>\FIRMWARE\ver 5.30\FWUP0028.DAT'),
    ('X-H2', 'new'): dict(version='5.33', dat=r'<корень проекта>\FIRMWARE\ver new\FWUP0028 (2).DAT'),
    ('X-H2S', 'old'): dict(version='7.30', dat=r'<корень проекта>\Firmware на прочиеFuji\FWUP0027.DAT'),
    ('X-H2S', 'new'): dict(version='7.31', dat=r'<корень проекта>\Firmware на прочиеFuji\FWUP0027(new).DAT'),
    ('X-T5', 'old'): dict(version='4.31', dat=r'<корень проекта>\Firmware на прочиеFuji\FWUP0030.DAT'),
    ('X-T5', 'new'): dict(version='4.32', dat=r'<корень проекта>\Firmware на прочиеFuji\FWUP0030(new).DAT'),
}

# флаг и структура состояния (определены в a1..a13)
M = {
    ('X-H2', 'old'): dict(flag=0x4c33f14, field_off=0x43c, state=0x4c33ad8,
                          movdc=0x3107e84, apply1=0x3108494, apply2=0x31089b8,
                          src=0x4c3f088, src_field=0x1e4, memcpy=0x3105440,
                          params_cur=0x4c3f1f8, params_pend=0x4c3f090,
                          mode=0x4c33af4, desc_off=0x488, slot_off=0x3a70),
    ('X-H2', 'new'): dict(flag=0x4c2ff14, field_off=0x43c, state=0x4c2fad8,
                          movdc=0x3103ff8, apply1=0x3104614, apply2=0x3104b50,
                          src=0x4c3b088, src_field=0x1e4, memcpy=0x31015b4,
                          params_cur=0x4c3b1f8, params_pend=0x4c3b090,
                          mode=0x4c2faf4, desc_off=0x488, slot_off=0x3a70),
    ('X-H2S', 'old'): dict(flag=0x4ba8f0c, field_off=0x434, state=0x4ba8ad8,
                           movdc=0x341a89c, apply1=0x341aea8, apply2=0x341b3b4,
                           src=0x4bb3e78, src_field=0x1ec, memcpy=0x34180f8,
                           params_cur=0x4bb3ff0, params_pend=0x4bb3e80,
                           mode=0x4ba8af4, desc_off=0x480, slot_off=0x3a68),
    ('X-H2S', 'new'): dict(flag=0x4ba8f0c, field_off=0x434, state=0x4ba8ad8,
                           movdc=0x341aa10, apply1=0x341b028, apply2=0x341b54c,
                           src=0x4bb3e78, src_field=0x1ec, memcpy=0x341826c,
                           params_cur=0x4bb3ff0, params_pend=0x4bb3e80,
                           mode=0x4ba8af4, desc_off=0x480, slot_off=0x3a68),
    ('X-T5', 'old'): dict(flag=0x4ab72c4, field_off=0x43c, state=0x4ab6e88,
                          movdc=0x3046748, apply1=0x3046d58, apply2=0x304727c,
                          src=0x4ac2730, src_field=0x284, memcpy=0x3043d08,
                          params_cur=0x4ac2940, params_pend=0x4ac2738,
                          mode=0x4ab6ea4, desc_off=0x488, slot_off=0x3d60),
    ('X-T5', 'new'): dict(flag=0x4ab72c4, field_off=0x43c, state=0x4ab6e88,
                          movdc=0x30468dc, apply1=0x3046ef8, apply2=0x3047434,
                          src=0x4ac2730, src_field=0x284, memcpy=0x3043e9c,
                          params_cur=0x4ac2940, params_pend=0x4ac2738,
                          mode=0x4ab6ea4, desc_off=0x488, slot_off=0x3d60),
}

GUARD = {
    ('X-H2', 'new'): (0x310420c, 0x3104210, 0x3104214),
    ('X-H2S', 'new'): (0x341ac2c, 0x341ac30, 0x341ac34),
    ('X-T5', 'new'): (0x3046af0, 0x3046af4, 0x3046af8),
}


def dis_lines(b, va, n):
    return [f'{i.address:x}: {i.mnemonic} {i.op_str}' for i in insns(b, va, n)]


def main():
    out = {'описание': 'MOVDC: флаг-снимок параметра, guard в LCD MOVDC-функции, '
                       'дескриптор вывода и VM-контроль. Все адреса — runtime VA блоков 0/1/2.',
           'модели': {}, 'доказательства': {}}

    # 1. флаг: все обращения во всех блоках
    for m in MODELS:
        for st in ('old', 'new'):
            key = f'{m} {st}'
            info = M[(m, st)]
            acc = {}
            for blk in (0, 1, 2):
                rows = scan_address(m, st, blk, info['flag'])
                acc[str(blk)] = rows
            out['модели'][key] = {
                'версия': META[(m, st)]['version'],
                'dat': META[(m, st)]['dat'],
                'флаг': hex(info['flag']),
                'поле_структуры': hex(info['field_off']),
                'база_структуры_состояния': hex(info['state']),
                'movdc_функция': hex(info['movdc']),
                'apply_функции': [hex(info['apply1']), hex(info['apply2'])],
                'режим_глобальный': hex(info['mode']),
                'указатель_дескриптора_поле': hex(info['desc_off']),
                'обращения_к_флагу': acc,
            }
            print(f'{key}: флаг {info["flag"]:#x}, обращений '
                  + ', '.join(f'b{k}={len(v)}' for k, v in acc.items()))

    # 2. guard: инструкции new
    for (m, st), (a1, a2, a3) in GUARD.items():
        b = load(m, st, 1)
        out['доказательства'][f'guard_{m}'] = {
            'инструкции': dis_lines(b, a1, 3),
            'чтение_флага_адрес': hex(a2),
            'ветвление_адрес': hex(a3),
        }

    # 3. полная цепочка источника флага
    for m in MODELS:
        info = M[(m, 'new')]
        b = load(m, 'new', 1)
        src_off = info['src_field']
        field_addr = info['src'] + src_off
        rows = scan_address(m, 'new', 1, field_addr)
        out['доказательства'][f'источник_{m}'] = {
            'адрес_поля_в_структуре_настроек': hex(field_addr),
            'смещение': hex(src_off),
            'чтения_поля': rows,
            'комментарий': 'писателей поля нет ни в блоке 0, ни в 1, ни в 2; '
                           'значение приходит извне/через API параметров',
        }

    # 4. memcpy pending->current
    for m in MODELS:
        info = M[(m, 'new')]
        b = load(m, 'new', 1)
        out['доказательства'][f'memcpy_параметров_{m}_new'] = {
            'функция': hex(info['memcpy']),
            'инструкции': dis_lines(b, info['memcpy'], 8),
            'pending': hex(info['params_pend']),
            'current': hex(info['params_cur']),
            'флаг_как_current_плюс_0x74': hex(info['params_cur'] + 0x74),
            'смысл': 'memcpy(pending -> current): флаг = current+0x74 во всех трёх моделях',
        }

    # 5. дескриптор вывода: где пишется, геттер геометрии
    GETTERS = {'X-H2': 0x310379c, 'X-H2S': None, 'X-T5': None}
    for m, st in [('X-H2', 'new'), ('X-H2S', 'new'), ('X-T5', 'new')]:
        info = M[(m, st)]
        bb = load(m, st, 1)
        out['доказательства'][f'дескриптор_{m}_{st}'] = {
            'указатель_по_адресу': hex(info['state'] + info['desc_off']),
            'структура': {'+0': 'height (из геометрии)', '+4': 'width (из геометрии)',
                          '+8': 'stride в байтах: new при flag!=0 -> 2*геометрия; '
                                'иначе наследуется p->[8]&~1',
                          '+0x10': 'указатель на пиксели (проверяется на !=0)',
                          '+0x18': 'размер/высота, используется при flush'},
            'режим_9_11_глобальный': hex(info['mode']),
        }
    # подтверждение геттера геометрии (640x480, stride-поле 0x280) по всем моделям
    out['доказательства']['геттер_геометрии_0x280'] = {
        'X-H2_new_функция': hex(0x310379c),
        'X-H2_new': dis_lines(load('X-H2', 'new', 1), 0x31037ec, 12),
        'X-T5_new_фрагмент': dis_lines(load('X-T5', 'new', 1), 0x3046318, 10),
        'X-H2S_new_фрагмент': dis_lines(load('X-H2S', 'new', 1), 0x341a44c, 10),
        'смысл': 'геттер пишет height=0x1e0(480), width=0x280(640), stride-поле=0x280(640); '
                 'MOVDC-функция затем пишет out[8] = 2*field = 1280',
    }

    # 6. VM-матрица
    vmrows = []
    for m in MODELS:
        for st in ('old', 'new'):
            for flag in (1, 0):
                for cur in (640, 1280):
                    r = vm.run(m, st, flag, cur)
                    vmrows.append({'модель': m, 'состояние': st, 'флаг': flag,
                                   'текущий_stride': cur, 'out': list(r['out']),
                                   'ошибка': r['err']})
    ctrl = []
    for m in MODELS:
        for st in ('old', 'new'):
            r = vm.run(m, st, 1, 640, buf_nonnull=False)
            ctrl.append({'модель': m, 'состояние': st, 'флаг': 1,
                         'текущий_stride': 640, 'буфер_пикселей': None,
                         'out': list(r['out'])})
    out['доказательства']['VM_unicorn'] = {
        'что_эмулируется': 'реальные инструкции участка MOVDC-функции: чтение p, '
                           'guard (new), запись out[0..2]; bl/blr заглушены',
        'матрица': vmrows,
        'контроль_без_пиксельного_буфера': ctrl,
        'вывод': 'old всегда наследует p->[8] (out[8]=p->[8]&~1) при flag=0 и flag=1; '
                 'new наследует при flag=0 и берёт 2*геометрия при flag=1; '
                 'при отсутствии пиксельного буфера обе версии дают 2*геометрия=1280',
    }

    # 6b. семантика out[8] (текстом, чтобы не путать с матрицей)
    out['доказательства']['семантика_out8'] = {
        'old_flag0': 'out[8] = p->[8] & ~1 (наследует; field присваивается в 0x3108098..0x31080a8 ДО проверки флага 0x31080fc)',
        'old_flag_ne0': 'out[8] = p->[8] & ~1',
        'new_flag0': 'out[8] = p->[8] & ~1 (как old)',
        'new_flag_ne0': 'out[8] = 2*geom = 1280 (guard 0x310420c..0x3104214 не даёт перезаписать field)',
        'если_p_или_буфер_нулевые': 'field остаётся равным геометрии => out[8]=2*geom=1280 в обеих версиях',
        'что_не_доказано': 'что унаследованный p->[8] в дефектном режиме был неверным; '
                           'при flag=0 значение 640 проходит без изменений в обеих версиях',
    }

    # 6c. VM развилок ccmp в apply1/apply2
    import a21_branch_vm as br
    def case(start, a, b, flag, pn):
        at, err = br.run_case(start, a, b, flag, pn)
        return {'адрес': hex(at) if at else None, 'ошибка': err}
    out['доказательства']['VM_развилок'] = {
        'apply1_0x3104754': {
            'flag=0,p!=0': case(0x3104754, 0x3104760, 0x31048d0, 0, 1),
            'flag=0,p==0': case(0x3104754, 0x3104760, 0x31048d0, 0, 0),
            'flag!=0,p!=0': case(0x3104754, 0x3104760, 0x31048d0, 1, 1),
            'flag!=0,p==0': case(0x3104754, 0x3104760, 0x31048d0, 1, 0),
        },
        'apply2_0x3104c5c': {
            'flag=0,p!=0': case(0x3104c5c, 0x3104c68, 0x3104c8c, 0, 1),
            'flag=0,p==0': case(0x3104c5c, 0x3104c68, 0x3104c8c, 0, 0),
            'flag!=0,p!=0': case(0x3104c5c, 0x3104c68, 0x3104c8c, 1, 1),
            'flag!=0,p==0': case(0x3104c5c, 0x3104c68, 0x3104c8c, 1, 0),
        },
        'трактовка': 'ветка (0x31048d0 / 0x3104c8c) берётся при flag==0 && p!=0; '
                     'в apply2 ветка затем делает b 0x3104c68 => MOVDC-функция вызывается всегда; '
                     'вызываемые там функции — заглушки ret, поэтому функционально no-op',
    }

    # 6d. ограничение интерпретации: детекция vs LCD
    out['доказательства']['ограничение_интерпретации'] = {
        'геометрия': '640x480 (0x1e0/0x280), типичный кадр детектора/АФ, а не LCD (~1.62 Мточки) и не live view',
        'строки_модуля': ['MOVDC_DETCTRL', 'C1BWind', 'C1BMask', 'C1BYCB', 'C1BYCR',
                          'C1AFea', 'C1AFeaW', 'C2AFcsN', 'C2AFcsD', 'C3ACsrM',
                          'RRS_Fx', 'RRS_Fe1', 'RRS_Fe2'],
        'геттер_геометрии_0x310379c_вызывается': ['0x3103c28', '0x3103e28', '0x3124e50',
                                                  '0x3124f38', '0x3124f94', '0x3103b10'],
        'потребитель_дескриптора': 'в блоках 0-2 кода, разыменовывающего указатель p, нет; '
                                   'указатель приходит из параметров (params+0x1c0/+0x1c8/+0x260)',
        'вывод': 'дескриптор скорее кадр детекции/АФ; связь неверного stride с видимыми '
                 'линиями на LCD — гипотеза, пока не найден потребитель/признак вывода на экран',
    }

    # 7. строки модуля
    out['доказательства']['строки_модуля'] = [
        'MOVDC', 'MOVDC FREEZE', 'MOVDC NOTICE', 'MOVDC_DETCTRL', 'AftAbrt',
        'NO_PLY', 'KEEP2!', 'MEMOVER!', 'C1BWind', 'C1BMask', 'C1BYCB', 'C1BYCR',
        'C1AFea', 'C2AFcsN', 'RRS_Fx', 'RRS_Fe2', 'LOCK:%d %d',
    ]

    path = os.path.join(HERE, 'доказательства.json')
    open(path, 'w', encoding='utf8').write(json.dumps(out, ensure_ascii=False, indent=1))
    print('\nзаписано:', path)


if __name__ == '__main__':
    main()
