# -*- coding: utf-8 -*-
"""Шаг 1: полные дизассемблирования трёх исправленных функций (блок 2) old/new
для трёх моделей + карта строк модуля pm_dec/DEC_STA/ProRes/FrameSize.

Запуск:  python c1_dump_funcs.py
Пишет:   c1_func_<model>_<state>.txt  и  c1_strings.json
"""
import sys, os, json
sys.path.insert(0, r'<корень проекта>\Анализ_прошивки\Сравнение_версий_2026-11-16')
from fwcommon import *  # noqa

HERE = os.path.dirname(os.path.abspath(__file__))

# известные точки входа (из КОНТЕКСТ.md): helper, prepare, completion
ANCH = {
    'X-H2':  {'old': (0x8fdac4, 0x8fdc20, 0x8fdf68), 'new': (0x8fda98, 0x8fdcd8, 0x8fe0d8)},
    'X-H2S': {'old': (0x8f0d5c, 0x8f0eb8, 0x8f1200), 'new': (0x8f0d30, 0x8f0f70, 0x8f1370)},
    'X-T5':  {'old': (0x8a2874, 0x8a29d0, 0x8a2d18), 'new': (0x8a2848, 0x8a2a88, 0x8a2e88)},
}
NAMES = ('helper_startcode', 'prepare_records', 'completion')


def full_func(b, va, max_insn=400):
    """Дизассемблируем от prologue до `ret` на нулевом уровне вложенности (эвристика)."""
    start = func_start(b, va) or va
    out, depth = [], 0
    for x in insns(b, start, max_insn):
        out.append(f'{x.address:x}: {x.mnemonic} {x.op_str}')
        if x.mnemonic in ('stp', 'str', 'sub') and 'sp' in x.op_str and '!' in x.op_str:
            depth += 1
        elif x.mnemonic in ('ldp', 'add') and x.op_str.startswith('sp, sp') and ']' in x.op_str and ', #' in x.op_str:
            depth = max(0, depth - 1)
        elif x.mnemonic == 'ret':
            break
    return start, out


def main():
    strings = {}
    for m in MODELS:
        for st in ('old', 'new'):
            b = load(m, st, 2)
            txt = [f'# {m} {st} block2  ({b!r})']
            for name, va in zip(NAMES, ANCH[m][st]):
                s, lines = full_func(b, va)
                txt.append(f'\n===== {name}: anchor {va:#x} start {s:#x} =====')
                txt.extend(lines)
            open(os.path.join(HERE, f'c1_func_{m}_{st}.txt'), 'w', encoding='utf8').write('\n'.join(txt) + '\n')

            # строки модуля
            hits = []
            for needle in (b'FrameSize', b'pm_dec', b'pm_enc', b'DEC_STA', b'ProRes', b'PRORES',
                           b'prores', b'PmDec', b'DEC_', b'Vdec', b'VDec', b'vdec', b'HEVC',
                           b'hevc', b'6K', b'stream', b'Stream', b'STREAM', b'ERROR', b'Error'):
                for va2 in find_bytes(b, needle):
                    s = b.cstr(va2, 120)
                    if s:
                        hits.append((hex(va2), s))
            strings[f'{m} {st}'] = sorted(set(hits))
    open(os.path.join(HERE, 'c1_strings.json'), 'w', encoding='utf8').write(
        json.dumps(strings, ensure_ascii=False, indent=1))
    # сводка в stdout
    for k, v in strings.items():
        print('=' * 10, k, len(v))
        for a, s in v:
            print(' ', a, repr(s[:110]))


if __name__ == '__main__':
    main()
