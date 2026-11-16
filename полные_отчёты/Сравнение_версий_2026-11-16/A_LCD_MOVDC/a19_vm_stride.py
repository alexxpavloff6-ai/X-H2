# -*- coding: utf-8 -*-
"""Шаг 19 (VM): контроль на Unicorn — какое значение stride попадает в дескриптор
вывода (out+8) в old и new при flag=0/1 и разном текущем stride дескриптора.

Эмулируются РЕАЛЬНЫЕ инструкции прошивки, начиная с участка чтения p=*(state+0x4xx)
(старая версия) или с guard-участка (новая), до записи out[0..8]. Вызовы bl/blr
заглушены (после них x0=0), стек и глобальные структуры предзаполнены:
  state+0xab     = 1            (взять основную ветку)
  mode_global    = 9            (режим 9..11, иначе ветка уводит)
  *(state+desc)  = DESC         (дескриптор вывода, out)
  DESC+0x00/04/08/0x10/0x18     (заполняются/проверяются)
  *(state+slot)  = не 0         (иначе запись дескриптора пропускается)
  [sp+geom..]    = 480/640/640  (геометрия: h, w, stride-поле от геттера 0x310379c)
Затем читаем DESC[0], DESC[1], DESC[2].

Ожидание: old(flag=1, cur_stride=640) -> 640 (дефект),
          new(flag=1, cur_stride=640) -> 1280 (исправление),
          flag=0 -> 640 и там, и там (guard не участвует),
          cur_stride=1280 -> 1280 везде.
"""
import sys, os, struct
sys.path.insert(0, r'<корень проекта>\Анализ_прошивки\Сравнение_версий_2026-11-16')
from fwcommon import *  # noqa
sys.path.insert(0, os.path.join(os.path.dirname(os.path.abspath(__file__)),
                                '..', 'инструменты'))
from unicorn import (Uc, UC_ARCH_ARM64, UC_MODE_LITTLE_ENDIAN, UC_HOOK_CODE,
                     UC_PROT_ALL)
from unicorn.arm64_const import (UC_ARM64_REG_X0, UC_ARM64_REG_SP,
                                 UC_ARM64_REG_X29, UC_ARM64_REG_X21,
                                 UC_ARM64_REG_X20, UC_ARM64_REG_PC)

HERE = os.path.dirname(os.path.abspath(__file__))
DESC = 0x4d000000
SLOT = 0x4d200000
STACK = 0x70000000
SP_INIT = STACK + 0x8000

# model, state -> параметры
P = {
    ('X-H2', 'old'): dict(entry=0x3107e84, start=0x310808c, stop=0x3108154,
                          flag=0x4c33f14, state=0x4c33ad8, desc_off=0x488,
                          slot_off=0x3a70, mode=0x4c33af4, geom=(0x164, 0x168, 0x16c)),
    ('X-H2', 'new'): dict(entry=0x3103ff8, start=0x3104200, stop=0x31042d4,
                          flag=0x4c2ff14, state=0x4c2fad8, desc_off=0x488,
                          slot_off=0x3a70, mode=0x4c2faf4, geom=(0x164, 0x168, 0x16c)),
    ('X-H2S', 'old'): dict(entry=0x341a89c, start=0x341aaac, stop=0x341ab74,
                           flag=0x4ba8f0c, state=0x4ba8ad8, desc_off=0x480,
                           slot_off=0x3a68, mode=0x4ba8af4, geom=(0x164, 0x168, 0x16c)),
    ('X-H2S', 'new'): dict(entry=0x341aa10, start=0x341ac20, stop=0x341acf4,
                           flag=0x4ba8f0c, state=0x4ba8ad8, desc_off=0x480,
                           slot_off=0x3a68, mode=0x4ba8af4, geom=(0x164, 0x168, 0x16c)),
    ('X-T5', 'old'): dict(entry=0x3046748, start=0x3046950, stop=0x3046a18,
                          flag=0x4ab72c4, state=0x4ab6e88, desc_off=0x488,
                          slot_off=0x3d60, mode=0x4ab6ea4, geom=(0x168, 0x16c, 0x170)),
    ('X-T5', 'new'): dict(entry=0x30468dc, start=0x3046ae4, stop=0x3046bb8,
                          flag=0x4ab72c4, state=0x4ab6e88, desc_off=0x488,
                          slot_off=0x3d60, mode=0x4ab6ea4, geom=(0x168, 0x16c, 0x170)),
}


def run(model, state, flag, cur_stride, buf_nonnull=True, verbose=False):
    p = P[(model, state)]
    b = load(model, state, 1)
    mu = Uc(UC_ARCH_ARM64, UC_MODE_LITTLE_ENDIAN)
    mapped = []

    def mapp(addr, size):
        """Постраничный маппинг (этот build unicorn плохо переносит большие
        mem_map и пересечения)."""
        p0 = addr & ~0xfff
        p1 = (addr + size + 0xfff) & ~0xfff
        for pg in range(p0, p1, 0x1000):
            if any(a <= pg < a + s for (a, s) in mapped):
                continue
            try:
                mu.mem_map(pg, 0x1000, UC_PROT_ALL)
            except Exception:
                print('MAPP FAIL', hex(pg),
                      'mapped:', [(hex(x), hex(y)) for x, y in mapped])
                raise
            mapped.append((pg, 0x1000))

    # код: окно вокруг эмулируемого участка + ветки на flag==0
    code_lo = (p['start'] - 0x2000) & ~0xfff
    code_len = (((p['stop'] + 0xa000) & ~0xfff) - code_lo)
    mapp(code_lo, code_len)
    off = code_lo - b.base
    mu.mem_write(code_lo, b.data[off:off + code_len])
    mapp(0x0, 0x1000)                       # нулевая страница (ldr [0])
    mapp(STACK, 0x20000)                    # стек
    mapp(p['flag'], 0x1000)
    mapp(p['mode'], 0x1000)
    mapp(p['state'], 0x1000)
    mapp(p['state'] + p['slot_off'], 0x1000)
    mapp(DESC, 0x1000)

    def w32(a, v):
        mu.mem_write(a, struct.pack('<I', v & 0xffffffff))

    def w64(a, v):
        mu.mem_write(a, struct.pack('<Q', v))

    w32(p['flag'], flag)
    w32(p['mode'], 9)
    mu.mem_write(p['state'] + 0xab, b'\x01')
    w64(p['state'] + p['desc_off'], DESC)
    w64(p['desc_off'] and p['state'] + p['slot_off'], SLOT)
    # дескриптор
    w32(DESC + 0x00, 0x11111111)
    w32(DESC + 0x04, 0x22222222)
    w32(DESC + 0x08, cur_stride)   # текущий stride дескриптора (source+8)
    w64(DESC + 0x10, 0x4d400000 if buf_nonnull else 0)   # указатель на пиксели (source+0x10)
    w64(DESC + 0x18, cur_stride * 480)
    # геометрия на стеке: (height, width, stride-поле)
    g0, g1, g2 = p['geom']
    w32(SP_INIT + g0, 480)
    w32(SP_INIT + g1, 640)
    w32(SP_INIT + g2, 640)

    mu.reg_write(UC_ARM64_REG_SP, SP_INIT)
    mu.reg_write(UC_ARM64_REG_X29, SP_INIT)
    mu.reg_write(UC_ARM64_REG_X20, 0)
    mu.reg_write(UC_ARM64_REG_X21, 0)

    log = []

    def hook(mu, addr, size, ud):
        try:
            w = struct.unpack('<I', bytes(mu.mem_read(addr, 4)))[0]
        except Exception:
            return
        if (w & 0xfc000000) == 0x94000000:      # BL
            mu.reg_write(UC_ARM64_REG_X0, 0)
            mu.reg_write(UC_ARM64_REG_PC, addr + 4)
            return
        if (w & 0xfffffc1f) == 0xd63f0000:      # BLR xn
            mu.reg_write(UC_ARM64_REG_X0, 0)
            mu.reg_write(UC_ARM64_REG_PC, addr + 4)
            return
        if verbose:
            log.append(addr)

    mu.hook_add(UC_HOOK_CODE, hook)
    err = None
    try:
        mu.emu_start(p['start'], p['stop'], count=2000)
    except Exception as e:  # noqa
        err = str(e)
    out = struct.unpack('<III', bytes(mu.mem_read(DESC, 12)))
    return {'model': model, 'state': state, 'flag': flag, 'cur': cur_stride,
            'out': out, 'err': err, 'steps': len(log)}


if __name__ == '__main__':
    rows = []
    for m in MODELS:
        for st in ('old', 'new'):
            for flag in (1, 0):
                for cur in (640, 1280):
                    r = run(m, st, flag, cur)
                    rows.append(r)
                    ok = '' if not r['err'] else '  ERR=' + r['err']
                    print(f"{m:6s} {st} flag={flag} cur_stride={cur:5d} -> "
                          f"out={{h={r['out'][0]}, w={r['out'][1]}, stride={r['out'][2]}}}{ok}")
    print()
    print('Контроль: пиксельного буфера нет (source+0x10 == 0):')
    for m in MODELS:
        for st in ('old', 'new'):
            r = run(m, st, 1, 640, buf_nonnull=False)
            print(f"  {m:6s} {st} flag=1 cur=640 buf=0 -> stride={r['out'][2]} (err={r['err']})")
    print()
    print('Сводка: out[8]')
    for r in rows:
        print(f"  {r['model']:6s} {r['state']} flag={r['flag']} cur={r['cur']:5d} -> {r['out'][2]}")
