# -*- coding: utf-8 -*-
"""Шаг 6: VM-контроль исправления PMFRM_SetStartCodeSlice2forAdvance.

Эмулируется РЕАЛЬНЫЙ код из блока 2 (Unicorn), старый и новый вариант, с
одинаковой раскладкой памяти. Сценарий — тот, который исправляет патч:

кадр-чанк (total байт) начинается в ПОСЛЕДНИХ d байтах сегмента (d=1..3),
поэтому его 4-байтовое big-endian поле длины slice1 «разрезано» границей:
первые d байт лежат в конце сегмента 1 (и скопированы в 4-байтовый слот
записи state+0x62c), остальные 4-d — в начале сегмента 2.

Аргументы helper'а (по вызовам из completion / prepare):
  x0 — адрес 4-байтового слота сохранённой длины (state+0x62c)
  x1 — указатель на начало чанка в сегменте 1 (в буфере)
  x2 — указатель продолжения (начало сегмента 2)
  w3 — сколько байт чанка доступно в сегменте 1 (d)
  w4 — полный размер чанка (total)

Ожидание: новый helper собирает поле из d байт слота и (4-d) байт сегмента 2,
проверяет len2+4+len1+4 == total и ставит start code 00 00 00 01 по адресу
второго поля (segment2 + (len1+4-d)). Старый helper читает 4 байта слота
целиком (мусор), уходит по неверному адресу, пишет start code в чужое место
и логирует FrameSizeError.

Запуск: python c6_vm_helper.py
Пишет:  c6_vm_results.json
"""
import sys, os, json, struct
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from c_common import *  # noqa
from unicorn import Uc, UC_ARCH_ARM64, UC_MODE_LITTLE_ENDIAN, UC_HOOK_CODE
from unicorn.arm64_const import (UC_ARM64_REG_X0, UC_ARM64_REG_X1, UC_ARM64_REG_X2,
                                 UC_ARM64_REG_X3, UC_ARM64_REG_X4, UC_ARM64_REG_SP,
                                 UC_ARM64_REG_LR, UC_ARM64_REG_PC, UC_ARM64_REG_W0)

HERE = os.path.dirname(os.path.abspath(__file__))
ANCH = {
    'X-H2':  {'old': (0x8fda98, 0x8fdc20), 'new': (0x8fda98, 0x8fdcd8)},
    'X-H2S': {'old': (0x8f0d30, 0x8f0eb8), 'new': (0x8f0d30, 0x8f0f70)},
    'X-T5':  {'old': (0x8a2848, 0x8a29d0), 'new': (0x8a2848, 0x8a2a88)},
}
FRAG1 = 0x10000000
FRAG2 = 0x10002000
SENT = 0x12345678
STACK = 0x70000000


def helper_and_logger(b, helper_va):
    """helper_va и адреса вызываемых из него функций (logger)."""
    logs = set()
    for x in insns(b, helper_va, 0x200 // 4):
        if x.mnemonic in ('bl', 'b') and x.op_str.startswith('#'):
            t = int(x.op_str[1:], 0)
            if x.mnemonic == 'bl':
                logs.add(t)
        if x.mnemonic == 'ret':
            break
    return helper_va, logs


def setup(b, helper_va, logger_addrs, slot_va, state_page, slot_bytes,
          frag1_bytes, frag2_bytes):
    uc = Uc(UC_ARCH_ARM64, UC_MODE_LITTLE_ENDIAN)
    uc.mem_map(0, len(b.data))
    uc.mem_write(0, b.data)
    uc.mem_map(state_page, 0x2000)
    uc.mem_map(FRAG1, 0x1000)
    uc.mem_map(FRAG2, 0x20000)
    uc.mem_map(STACK, 0x10000)
    uc.mem_write(FRAG1, bytes(frag1_bytes).ljust(0x1000, b'\0'))
    uc.mem_write(FRAG2, bytes(frag2_bytes))
    if not (state_page <= slot_va < state_page + 0x2000):
        uc.mem_map(slot_va & ~0xfff, 0x1000)
    uc.mem_write(slot_va, bytes(slot_bytes))
    uc.reg_write(UC_ARM64_REG_SP, STACK + 0x8000)
    uc.reg_write(UC_ARM64_REG_LR, SENT)
    log = []

    def hcode(uc_, addr, sz, ud):
        if addr == SENT:
            uc_.emu_stop()
        elif addr in logger_addrs:
            p = uc_.reg_read(UC_ARM64_REG_X0)
            s = None
            try:
                raw = uc_.mem_read(p, 120)
                s = raw.split(b'\0', 1)[0].decode('latin1')
            except Exception:
                pass
            log.append({'string_va': hex(p), 'string': s})
            uc_.reg_write(UC_ARM64_REG_PC, uc_.reg_read(UC_ARM64_REG_LR))

    for la in logger_addrs:
        uc.hook_add(UC_HOOK_CODE, hcode, begin=la, end=la)
    uc.hook_add(UC_HOOK_CODE, hcode, begin=SENT, end=SENT)
    return uc, log


def run(b, helper_va, logger_addrs, slot_va, state_page, args,
        slot_bytes, frag1_bytes, frag2_bytes, max_insn=500):
    uc, log = setup(b, helper_va, logger_addrs, slot_va, state_page, slot_bytes,
                    frag1_bytes, frag2_bytes)
    for reg, val in zip((UC_ARM64_REG_X0, UC_ARM64_REG_X1, UC_ARM64_REG_X2,
                         UC_ARM64_REG_X3, UC_ARM64_REG_X4), args):
        uc.reg_write(reg, val)
    err = None
    try:
        uc.emu_start(helper_va, SENT, count=max_insn)
    except Exception as e:  # noqa
        err = str(e)
    out = {'fault': err, 'w0': uc.reg_read(UC_ARM64_REG_W0) & 0xffffffff,
           'logs': log, 'slot_after': uc.mem_read(slot_va, 4).hex()}
    return out, uc


def be32(v):
    return struct.pack('>I', v)


def scen_straddle(d=2, total=0x1234, len1=0x100):
    len2 = total - 8 - len1
    l1 = be32(len1)
    slot = l1[:d] + b'\xAA' * (4 - d)
    frag2 = bytearray(0x20000)
    frag2[0:4 - d] = l1[d:]
    off2 = len1 + 4 - d
    frag2[off2:off2 + 4] = be32(len2)
    return dict(d=d, total=total, len1=len1, len2=len2, slot=slot,
                frag1=bytes(0x1000), frag2=bytes(frag2), off2=off2,
                wrong_off=0xAAAC)


def scen_plain(total=0x1234, len1=0x100):
    len2 = total - 8 - len1
    frag1 = bytearray(0x1000)
    frag1[0:4] = be32(len1)
    frag1[0x104:0x108] = be32(len2)
    return dict(d=total, total=total, len1=len1, len2=len2, slot=be32(len1),
                frag1=bytes(frag1), frag2=bytes(0x20000), off2=None,
                wrong_off=None)


def main():
    res = {}
    for m in MODELS:
        for st in ('old', 'new'):
            b = load(m, st, 2)
            helper_va, logger_addrs = helper_and_logger(b, ANCH[m][st][0])
            page, base = find_state_base(b, ANCH[m][st][1])
            slot_va = u64(page + base + 0x62C)
            for tag, s in (('straddle d=2', scen_straddle(2)),
                           ('plain', scen_plain()),
                           ('straddle d=0', scen_straddle(0)),
                           ('straddle d=1', scen_straddle(1)),
                           ('straddle d=3', scen_straddle(3))):
                args = [slot_va, FRAG1, FRAG2, s['d'], s['total']]
                out, uc = run(b, helper_va, logger_addrs, slot_va, u64(page), args,
                              s['slot'], s['frag1'], s['frag2'])
                # что записалось в ожидаемое и «мусорное» места
                def rd(va):
                    try:
                        return uc.mem_read(va, 4).hex()
                    except Exception:
                        return None
                out['expected_field_va'] = (hex(FRAG2 + s['off2'])
                                            if s['off2'] is not None else hex(FRAG1 + 0x104))
                out['field_ok'] = (rd(FRAG2 + s['off2']) if s['off2'] is not None
                                   else rd(FRAG1 + 0x104)) == '00000001'
                out['wrong_field_hex'] = rd(FRAG2 + 0xAAAC)
                out['wrong_touched'] = out['wrong_field_hex'] not in (None, '00000000')
                out.update({'model': m, 'state': st, 'scenario': tag,
                            'helper': hex(helper_va), 'slot': hex(slot_va),
                            'logger': [hex(a) for a in sorted(logger_addrs)],
                            'd': s['d'], 'total': s['total'],
                            'len1': s['len1'], 'len2': s['len2']})
                res[f'{m} {st} {tag}'] = out
    for k, v in res.items():
        print(f"{k:26s} fault={str(v['fault'])[:34]:34s} w0={v['w0']:#010x} "
              f"field_ok={str(v['field_ok']):5s} wrong={str(v['wrong_touched']):5s} "
              f"logs={[l['string'] for l in v['logs']]}")
    open(os.path.join(HERE, 'c6_vm_results.json'), 'w', encoding='utf8').write(
        json.dumps(res, ensure_ascii=False, indent=1))


if __name__ == '__main__':
    main()
