"""VM-контроль ключевых веток патча «lens 0x411 / MF linear» (Unicorn).

Проверяется ПОВЕДЕНИЕ КОДА, а не интерпретация:
  VM-1 (new): ветка обработчика MF-операций в диспетчере lens-запроса.
              Вход: request->op, request+0x50 (флаг «lens==0x411»), значения свойств.
              Выход: output+0xa0 (u16) и output+0x50 (u16).
  VM-2 (old): та же точка в старой прошивке — значения берутся из свойств.
  VM-3 (new): сохранение флага: cmp w21,#0x411 ; cset ; str [sp,#0xb0].

Геттеры свойств подменяются хуком (bl не выполняется, x0 = подставленное значение).

Запуск:  python vm_focus.py            — все модели, все случаи
         python vm_focus.py --json     — плюс vm_results.json
Только чтение блоков; отчёты пишутся только в эту папку.
"""
import json
import struct
import sys
from pathlib import Path

HERE = Path(__file__).resolve().parent
sys.path.insert(0, str(HERE.parent))
from fwcommon import load  # noqa: E402
import capstone  # noqa: E402
from unicorn import Uc, UC_ARCH_ARM64, UC_MODE_LITTLE_ENDIAN, UC_HOOK_CODE  # noqa: E402
from unicorn.arm64_const import (UC_ARM64_REG_SP, UC_ARM64_REG_PC,  # noqa: E402
                                 UC_ARM64_REG_X0, UC_ARM64_REG_W0, UC_ARM64_REG_W1,
                                 UC_ARM64_REG_W8, UC_ARM64_REG_W20, UC_ARM64_REG_W21,
                                 UC_ARM64_REG_W22, UC_ARM64_REG_W23, UC_ARM64_REG_W24)

D = capstone.Cs(capstone.CS_ARCH_ARM64, capstone.CS_MODE_LITTLE_ENDIAN)

# --- точки входа/выхода (b1_locate.py + ручная сверка) ----------------------
SITES = {
    ('X-H2', 'new'): dict(start=0x2ce8b34, tail=0x2ce8ca0, req_slot=0xc0,
                          u8=0x14920fc, u16=0x14921bc, flag_slot=0xb0,
                          flag_code=0x2dec9b0),
    ('X-H2', 'old'): dict(start=0x2cecb34, tail=0x2cecca0, req_slot=0xc0,
                          u8=0x149b0cc, u16=0x149b18c, flag_slot=0x68,
                          flag_code=0x2df093c),
    ('X-H2S', 'new'): dict(start=0x3004458, tail=0x30045d0, req_slot=0xd0,
                           u8=0x17bac68, u16=0x17bad28, flag_slot=0xb0,
                           flag_code=0x3107fe8),
    ('X-H2S', 'old'): dict(start=0x3004458, tail=0x3004494, req_slot=0xd0,
                           u8=0x17bac60, u16=0x17bad20, flag_slot=0x68,
                           flag_code=0x3107f74),
    ('X-T5', 'new'): dict(start=0x2c2b7f8, tail=0x2c2b970, req_slot=0xc0,
                          u8=0x14951a4, u16=0x1495264, flag_slot=0xb0,
                          flag_code=0x2d2e04c),
    ('X-T5', 'old'): dict(start=0x2c2b7f8, tail=0x2c2b964, req_slot=0xc0,
                          u8=0x149519c, u16=0x149525c, flag_slot=0x68,
                          flag_code=0x2d2dfc8),
}

STACK = 0x30000000
DATA = 0x40000000
OUT = DATA + 0x1000
REQ = DATA + 0x2000


def _bl_map(b, lo, hi):
    out = {}
    for i in D.disasm(b.data[b.off(lo):b.off(hi)], lo):
        if i.mnemonic == 'bl':
            out[i.address] = int(i.op_str.lstrip('#'), 0)
    return out


def _uc_code(b):
    uc = Uc(UC_ARCH_ARM64, UC_MODE_LITTLE_ENDIAN)
    cb = b.base & ~0xfff
    csize = ((len(b.data) + 0x1000) + 0xfff) & ~0xfff
    uc.mem_map(cb, csize)
    uc.mem_write(cb, b.data + b'\0' * (csize - len(b.data)))
    return uc


def emu_branch(model, state, op, flag, props, classv=1):
    s = SITES[(model, state)]
    b = load(model, state, 1)
    bls = _bl_map(b, s['start'], s['tail'] + 0x400)
    uc = _uc_code(b)
    uc.mem_map(STACK, 0x20000)
    uc.mem_map(DATA, 0x10000)
    sp0 = STACK + 0x10000
    uc.mem_write(sp0 + 0xa0, struct.pack('<Q', OUT))
    uc.mem_write(sp0 + s['req_slot'], struct.pack('<Q', REQ))
    uc.mem_write(sp0 + 0xe4, struct.pack('<I', classv))
    req = bytearray(0x70)
    struct.pack_into('<I', req, 0x00, op)
    struct.pack_into('<I', req, 0x50, flag)
    uc.mem_write(REQ, bytes(req))
    uc.mem_write(OUT, bytes(0xa8))
    pv = dict(props)
    stop_pc = s['tail'] + 12
    st = {'n': 0}
    u8g, u16g = s['u8'], s['u16']

    def hook(uc_, addr, size, _):
        st['n'] += 1
        if addr == stop_pc:
            uc_.emu_stop()
            return
        if addr in bls:
            tgt = bls[addr]
            pid = uc_.reg_read(UC_ARM64_REG_X0) & 0xffffff
            if tgt == u8g:
                uc_.reg_write(UC_ARM64_REG_X0, pv.get(pid, 0) & 0xff)
            elif tgt == u16g:
                uc_.reg_write(UC_ARM64_REG_X0, pv.get(pid, 0) & 0xffff)
            else:
                uc_.reg_write(UC_ARM64_REG_X0, 0)
            uc_.reg_write(UC_ARM64_REG_PC, addr + 4)

    uc.hook_add(UC_HOOK_CODE, hook)
    uc.reg_write(UC_ARM64_REG_SP, sp0)
    try:
        uc.emu_start(s['start'], stop_pc, count=500000)
    except Exception as e:  # noqa: BLE001
        return dict(error=str(e), steps=st['n'], model=model, state=state,
                    op=op, flag=flag)
    raw = uc.mem_read(OUT, 0xa8)
    return dict(model=model, state=state, op=op, flag=flag,
                out_a0=struct.unpack_from('<H', raw, 0xa0)[0],
                out_50=struct.unpack_from('<H', raw, 0x50)[0],
                steps=st['n'], stop_pc=hex(stop_pc))


def _cmp_reg(b, va):
    rn = (b.u32(va) >> 5) & 0x1f
    m = {0: UC_ARM64_REG_W0, 1: UC_ARM64_REG_W1, 8: UC_ARM64_REG_W8,
         20: UC_ARM64_REG_W20, 21: UC_ARM64_REG_W21, 22: UC_ARM64_REG_W22,
         23: UC_ARM64_REG_W23, 24: UC_ARM64_REG_W24}
    if rn not in m:
        raise SystemExit('cmp w%d не поддержан в VM' % rn)
    return m[rn]


def emu_flag(model, state, lens_id):
    s = SITES[(model, state)]
    b = load(model, state, 1)
    uc = _uc_code(b)
    uc.mem_map(STACK, 0x20000)
    sp0 = STACK + 0x10000
    uc.mem_write(sp0 + s['flag_slot'], struct.pack('<I', 0xdeadbeef))
    uc.reg_write(_cmp_reg(b, s['flag_code']), lens_id & 0xffffffff)
    uc.reg_write(UC_ARM64_REG_SP, sp0)
    start = s['flag_code']
    try:
        uc.emu_start(start, start + 12, count=100)
    except Exception as e:  # noqa: BLE001
        return dict(error=str(e), model=model, state=state, lens=hex(lens_id))
    val = struct.unpack('<I', uc.mem_read(sp0 + s['flag_slot'], 4))[0]
    return dict(model=model, state=state, lens=hex(lens_id), flag=val)


PROPS_A = {0x1db2: 1, 0x1db3: 0, 0x1dba: 0, 0x1db8: 0x11, 0x1dbc: 0,
           0x2059: 128, 0x205a: 140, 0x205c: 0, 0x205e: 228}
PROPS_B = {0x1db2: 1, 0x1db3: 140, 0x1dba: 228, 0x1db8: 0x11, 0x1dbc: 0,
           0x2059: 128, 0x205a: 140, 0x205c: 0, 0x205e: 228}
PROPS_Z = {0x1db2: 0, 0x1db3: 0, 0x1dba: 0, 0x1db8: 0, 0x1dbc: 0,
           0x2059: 0, 0x205a: 0, 0x205c: 0, 0x205e: 0}

# операции, которые в этой модели идут по MF-ветке (см. отчёт: tst/sub или битовая маска)
MF_OPS = {'X-H2': [0x1e, 0x20], 'X-H2S': [0x1b, 0x1d, 0x1f, 0x21, 0x23],
          'X-T5': [0x1e, 0x20]}
NONMF = {'X-H2': 0x1f, 'X-H2S': 0x1e, 'X-T5': 0x1f}


def cases_for(model):
    mf, nmf = MF_OPS[model][0], NONMF[model]
    newc = [(mf, 1, PROPS_A, 'MF-op, flag=1'),
            (mf, 0, PROPS_A, 'MF-op, flag=0'),
            (mf, 1, PROPS_Z, 'MF-op, flag=1, свойства=0'),
            (nmf, 1, PROPS_A, 'не-MF op, flag=1')]
    oldc = [(mf, 1, PROPS_A, 'MF-op, свойства=0'),
            (mf, 1, PROPS_B, 'MF-op, свойства 140/228'),
            (nmf, 1, PROPS_A, 'не-MF op, свойства=0')]
    return newc, oldc


def fmt(r):
    if 'out_a0' not in r:
        return 'ERR ' + r.get('error', '')
    return 'out+a0=%#06x out+50=%#06x (шагов %d)' % (r['out_a0'], r['out_50'], r['steps'])


if __name__ == '__main__':
    try:
        sys.stdout.reconfigure(encoding='utf-8', errors='replace')
    except Exception:  # noqa: BLE001
        pass
    res = {'vm1_new': [], 'vm2_old': [], 'vm3_flag': []}
    for model in ('X-H2', 'X-H2S', 'X-T5'):
        newc, oldc = cases_for(model)
        for op, flag, pr, name in newc:
            r = emu_branch(model, 'new', op, flag, pr)
            r['case'] = name
            res['vm1_new'].append(r)
            print('VM1 %-6s op=%#04x %-30s %s' % (model, op, name, fmt(r)))
        for op, flag, pr, name in oldc:
            r = emu_branch(model, 'old', op, flag, pr)
            r['case'] = name
            res['vm2_old'].append(r)
            print('VM2 %-6s op=%#04x %-30s %s' % (model, op, name, fmt(r)))
        for lid in (0x411, 0x410, 0x412):
            r = emu_flag(model, 'new', lid)
            res['vm3_flag'].append(r)
            print('VM3 %-6s lens=%s -> flag=%s' % (model, r['lens'], r.get('flag')))
    if '--json' in sys.argv:
        (HERE / 'vm_results.json').write_text(
            json.dumps(res, indent=1, ensure_ascii=False), encoding='utf8')
        print('saved vm_results.json')
