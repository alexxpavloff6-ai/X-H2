# -*- coding: utf-8 -*-
"""Шаг 8: точные адреса ключевых мест по трём моделям (для отчёта).

Печатает:
  * helper: адрес проверки `cmp w3,#3` (диспетчер разрезки поля по границе),
    адреса ссылок на строки PreSizeError / FrameSizeError;
  * prepare: сравнение «чанк не влезает в сегмент» ([ST+0x18] < remaining);
  * completion: ссылку на строку H265 FinFrameDataSizeError;
  * состояние: page/base ST и адреса инициализации [ST+0x18] (0xC000000/0x4000000).
Запуск: python c8_key_addrs.py  (пишет c8_key_addrs.json)
"""
import sys, os, json, re
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from c_common import *  # noqa

HERE = os.path.dirname(os.path.abspath(__file__))
ANCH = {
    'X-H2':  {'old': (0x8fda98, 0x8fdc20, 0x8fdf68), 'new': (0x8fda98, 0x8fdcd8, 0x8fe0d8)},
    'X-H2S': {'old': (0x8f0d30, 0x8f0eb8, 0x8f1200), 'new': (0x8f0d30, 0x8f0f70, 0x8f1370)},
    'X-T5':  {'old': (0x8a2848, 0x8a29d0, 0x8a2d18), 'new': (0x8a2848, 0x8a2a88, 0x8a2e88)},
}
STRINGS = {
    'old': [b'PreSizeError', b'PMFRM:PMFRM_SetStartCodeSlice2forAdvance:FrameSizeError'],
    'new': [b'PMFRM_SetStartCodeSlice2forAdvance:PreSizeError',
            b'PMFRM:PMFRM_SetStartCodeSlice2forAdvance:FrameSizeError',
            b'PMFRM_AfterDataReadForH265:FinFrameDataSizeError'],
}


def str_ref(b, needle):
    """Адреса инструкций adrp+add, ссылающихся на строку needle."""
    hits = find_bytes(b, needle)
    out = []
    for h in hits:
        s = h
        while s > h - 200 and b.data[b.off(s) - 1] != 0:
            s -= 1
        # ищем adrp+add на s
        for x in insns(b, s - 0x400 if s > 0x400 else 0, 0x400 // 4):
            if x.mnemonic == 'adrp':
                page = int(x.op_str.split('#')[1], 0)
                reg = x.op_str.split(',')[0]
                if (page & 0xfff) != (s & 0xfff):
                    # adrp даёт страницу; add добавит младшие 12 бит
                    if (page & ~0xfff) != (s & ~0xfff):
                        continue
                for y in insns(b, x.address + 4, 2):
                    if y.mnemonic == 'add' and y.op_str.startswith(f'{reg}, {reg}, #'):
                        if page + int(y.op_str.split('#')[1], 0) == s:
                            out.append((y.address, s))
                        break
    return sorted(set(out))


def main():
    res = {}
    for m in MODELS:
        res[m] = {}
        for st in ('old', 'new'):
            b = load(m, st, 2)
            h, p, c = ANCH[m][st]
            page, base = find_state_base(b, p)
            rec = {'helper': hex(h), 'prepare': hex(p), 'completion': hex(c),
                   'state_page': hex(page), 'state_base': hex(base),
                   'strings': {}}
            for needle in STRINGS[st]:
                for site, s in str_ref(b, needle):
                    rec['strings'].setdefault(needle.decode(), []).append(
                        {'site': hex(site), 'string': hex(s)})
            # cmp w3,#3 в helper
            for x in insns(b, h, 0x20):
                if x.mnemonic == 'cmp' and x.op_str == 'w3, #3':
                    rec['helper_dispatch'] = hex(x.address)
                if x.mnemonic == 'sub' and x.op_str == 'w4, w4, w19':
                    rec['helper_split_sub'] = hex(x.address)
            # init ST+0x18 = 0xC000000 / 0x4000000
            for x in insns(b, 0x8fd060, 0x40):
                if x.mnemonic == 'mov' and x.op_str in ('w1, #0xc000000', 'w1, #0x4000000'):
                    rec.setdefault('init_seg_len', []).append(
                        {'mov': hex(x.address), 'imm': x.op_str})
            res[m][st] = rec
    for m in MODELS:
        print('===', m)
        for st in ('old', 'new'):
            r = res[m][st]
            print(f"  {st}: helper {r['helper']} (dispatch {r.get('helper_dispatch')}), "
                  f"prepare {r['prepare']}, completion {r['completion']}, "
                  f"ST=page{r['state_page']}+{r['state_base']}"
                  f"{'  seg=' + str(r.get('init_seg_len')) if r.get('init_seg_len') else ''}")
            for k, v in r['strings'].items():
                print('     ', k, '->', v)
    open(os.path.join(HERE, 'c8_key_addrs.json'), 'w', encoding='utf8').write(
        json.dumps(res, ensure_ascii=False, indent=1))


if __name__ == '__main__':
    main()
