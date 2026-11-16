# -*- coding: utf-8 -*-
"""D: VM-контроль (Unicorn) двух выводов.

 1) Вставка патча (mov w0,#0x9155 ... str w0,[x22,#0x80]) читает u16 из blob по
    смещению 0x19155 и пишет (значение & 0xFFFF) << 9 в commit+0x80; при w24 == 0
    запись в commit+0x80 не производится (только params+0x60).
 2) Копировщик commit->per-frame пишет commit+0x80 в per-frame+<off> только когда
    у байта blob[0xa8] выставлен бит 7; иначе выходит, ничего не записав.

Методика: эмуляция оригинальных инструкций из blocks/*.bin; вход — либо адрес
вставки, либо вход функции-копировщика (по прологу); остановка — сразу после
интересующих записей или по возврату в ловушку (LR = `b .`).
Запуск: python 19_vm.py   (пишет vm_results.json)
"""
import sys, re, struct, json
sys.path.insert(0, r'<корень проекта>\Анализ_прошивки\Сравнение_версий_2026-11-16\D_брекетинг')
from dhelp import *  # noqa
from unicorn import Uc, UC_ARCH_ARM64, UC_MODE_ARM, UC_HOOK_MEM_UNMAPPED, UC_HOOK_CODE
from unicorn.arm64_const import *

BLOB_BASE = 0x27008000
BLOB_SIZE = 0x200000
STACK = 0x70000000
STACK_SIZE = 0x40000
TRAP = 0x70100000
PAGE = 0x1000

def movz(reg, imm, hw=0):
    return 0x52800000 | (hw << 21) | (imm << 5) | reg

def movk(reg, imm, hw=0):
    return 0x72800000 | (hw << 21) | (imm << 5) | reg

GROUP = struct.pack('<II', movz(0, 0x916f), movk(0, 1, 1))
PATCH = struct.pack('<II', movz(0, 0x9155), movk(0, 1, 1))

def find_getter(model, state):
    b1 = load(model, state, 1)
    g = find_bytes(b1, GROUP)[0]
    x = insns(b1, g + 8, 1)[0]
    return int(x.op_str.split('#')[1], 0)

def blob_global(model, state, getter):
    b0 = load(model, state, 0)
    byteget = None
    for x in insns(b0, getter, 8):
        if x.mnemonic == 'bl':
            byteget = int(x.op_str.split('#')[1], 0)
            break
    if byteget is None:
        return None
    page = None
    for x in insns(b0, byteget, 8):
        if x.mnemonic == 'adrp':
            page = int(x.op_str.split('#')[1], 0)
        m = re.search(r'\[x\d+, #0x([0-9a-f]+)\]', x.op_str)
        if x.mnemonic == 'ldr' and m and page:
            return page + int(m.group(1), 16)
    return None

def find_copier(model, state):
    """Возвращает (entry, off_в_кадрах, база_таблицы) для копировщика commit->per-frame."""
    b1 = load(model, state, 1)
    d = b1.data
    for o in range(0, len(d) - 12, 4):
        if struct.unpack_from('<I', d, o)[0] != movz(0, 0xa8):
            continue
        w1, w2 = struct.unpack_from('<II', d, o + 4)
        if (w1 & 0xfc000000) != 0x94000000:
            continue
        if (w2 & 0x7f000000) != 0x37000000 or ((w2 >> 19) & 0x1f) != 7 or (w2 & 0x1f) != 0:
            continue
        ins = insns(b1, b1.base + o, 80)
        txt = '\n'.join(f'{x.mnemonic} {x.op_str}' for x in ins)
        if 'ldr w2, [x20, #0x80]' not in txt:
            continue
        # смещение в кадре
        frame_off = None
        for i, x in enumerate(ins):
            if x.mnemonic == 'ldr' and x.op_str == 'w2, [x20, #0x80]':
                for y in ins[i + 1:i + 3]:
                    mm = re.search(r'\[x\d+, #0x([0-9a-f]+)\]$', y.op_str)
                    if y.mnemonic == 'str' and mm:
                        frame_off = int(mm.group(1), 16)
                        break
        # база таблицы: add x0, x0, x3 при известном x3 (movz+movk)
        base = 0
        for i, x in enumerate(ins):
            if x.mnemonic == 'add' and x.op_str == 'x0, x0, x3':
                for y in ins[max(0, i - 4):i]:
                    if y.mnemonic == 'movk' and y.op_str.startswith('x3, #') and 'lsl #16' in y.op_str:
                        hi = int(y.op_str.split('#')[1].split(',')[0], 0)
                        base |= hi << 16
                    elif y.mnemonic == 'mov' and y.op_str.startswith('x3, #'):
                        lo = int(y.op_str.split('#')[1].split(',')[0], 0)
                        base |= lo
                break
        entry = None
        for k in range(o - 4, o - 0x400, -4):
            if struct.unpack_from('<I', d, k)[0] == 0xd65f03c0:
                entry = b1.base + k + 4
                break
        return entry, frame_off, base
    return None, None, None

class VM:
    def __init__(self, model, state, blob_ptr):
        b0, b1 = load(model, state, 0), load(model, state, 1)
        self.uc = Uc(UC_ARCH_ARM64, UC_MODE_ARM)
        self.b1 = b1
        for blk in (b0, b1):
            n = (len(blk.data) + PAGE - 1) & ~(PAGE - 1)
            self.uc.mem_map(blk.base, n)
            self.uc.mem_write(blk.base, blk.data)
        self.uc.mem_map(BLOB_BASE, BLOB_SIZE)
        self.uc.mem_write(BLOB_BASE, bytes(BLOB_SIZE))
        self.uc.mem_map(STACK, STACK_SIZE)
        self.uc.mem_map(TRAP, PAGE)
        self.uc.mem_write(TRAP, struct.pack('<I', 0x14000000))
        self.uc.mem_map(blob_ptr & ~(PAGE - 1), PAGE)
        self.uc.mem_write(blob_ptr, struct.pack('<Q', BLOB_BASE))
        self.uc.hook_add(UC_HOOK_MEM_UNMAPPED, self._unmapped)
        self.n = 0
        self.stops = set()
        self.uc.hook_add(UC_HOOK_CODE, self._code)

    def _unmapped(self, uc, access, address, size, value, user):
        try:
            uc.mem_map(address & ~(PAGE - 1), 0x10000)
            return True
        except Exception:
            try:
                uc.mem_map(address & ~(PAGE - 1), PAGE)
                return True
            except Exception:
                return False

    def _code(self, uc, address, size, user):
        if address == TRAP:
            uc.emu_stop(); return
        if address in self.stops:
            uc.emu_stop(); return
        self.n += 1
        if self.n > 300000:
            uc.emu_stop()

    def blob(self, off, val, width):
        fmt = {1: '<B', 2: '<H', 4: '<I'}[width]
        self.uc.mem_write(BLOB_BASE + off, struct.pack(fmt, val))

    def buf(self, addr, data):
        n = max(PAGE, (len(data) + PAGE - 1) & ~(PAGE - 1))
        self.uc.mem_map(addr, n)
        self.uc.mem_write(addr, bytes(data))

    def run(self, entry, regs, lr=None, sp=None):
        for r, v in regs.items():
            self.uc.reg_write(r, v)
        self.uc.reg_write(UC_ARM64_REG_SP, sp if sp is not None else STACK + STACK_SIZE - 0x200)
        self.uc.reg_write(UC_ARM64_REG_LR, lr if lr is not None else TRAP)
        try:
            self.uc.emu_start(entry, TRAP, 0, 300000)
            return None
        except Exception as e:
            return str(e)

    def rd(self, addr, width=4):
        try:
            fmt = {1: '<B', 2: '<H', 4: '<I'}[width]
            return struct.unpack(fmt, self.uc.mem_read(addr, width))[0]
        except Exception:
            return None

res = {}
for m in MODELS:
    for st in ('old', 'new'):
        key = f'{m} {st}'
        b1 = load(m, st, 1)
        getter = find_getter(m, st)
        g = blob_global(m, st, getter)
        patch = find_bytes(b1, PATCH)
        copier, frame_off, frame_base = find_copier(m, st)
        res[key] = {'getter': hex(getter), 'blob_global': hex(g), 'patch': [hex(x) for x in patch],
                    'copier': hex(copier) if copier else None, 'copier_frame_off': frame_off,
                    'copier_frame_base': hex(frame_base or 0)}
        print(f'{key}: getter={getter:#x} blob={g:#x} patch={[hex(x) for x in patch]} '
              f'copier={copier and hex(copier)} frame_off={frame_off and hex(frame_off)}')

        # ---------- VM 1: вставка патча ----------
        if patch:
            pa = patch[0]
            ins = insns(b1, pa, 16)
            cbz = [x for x in ins if x.mnemonic == 'cbz']
            cbz_tgt = int(cbz[0].op_str.split('#')[-1], 0) if cbz else None
            params, commit = 0x40001000, 0x40002000
            for w24 in (1, 0):
                for val in (0, 1, 0x1234, 0xffff):
                    vm = VM(m, st, g)
                    vm.buf(params, bytes(0x400)); vm.buf(commit, bytes(0x400))
                    vm.blob(0xa8, 0x80, 1); vm.blob(0x19155, val, 2)
                    vm.stops = {pa + 0x1c} | ({cbz_tgt} if cbz_tgt else set())
                    err = vm.run(pa, {UC_ARM64_REG_X19: params, UC_ARM64_REG_X22: commit,
                                      UC_ARM64_REG_X24: w24})
                    out = {'err': err,
                           'params+0x60': hex(vm.rd(params + 0x60) or 0),
                           'commit+0x80': hex(vm.rd(commit + 0x80) or 0),
                           'insn': vm.n}
                    res[key].setdefault('vm_patch', []).append(
                        {'blob[0x19155]': hex(val), 'w24': w24, **out})
                    print(f'   patch VM v={val:#06x} w24={w24}: {out}')

        # ---------- VM 2: копировщик ----------
        if copier:
            commit, dst = 0x40002000, 0x40010000
            for a8 in (0x80, 0x00):
                for v in (0, 0x246800):
                    vm = VM(m, st, g)
                    img = bytearray(0x400)
                    struct.pack_into('<I', img, 0x80, v)
                    vm.buf(commit, img); vm.buf(dst, bytes(0x800000))
                    vm.blob(0xa8, a8, 1)
                    err = vm.run(copier, {UC_ARM64_REG_X0: commit, UC_ARM64_REG_X1: dst,
                                          UC_ARM64_REG_X2: 0})
                    got = vm.rd(dst + (frame_base or 0) + frame_off) if frame_off is not None else None
                    out = {'err': err, 'per-frame+%#x' % frame_off: got, 'insn': vm.n}
                    res[key].setdefault('vm_copier', []).append(
                        {'blob[0xa8]': hex(a8), 'commit+0x80': hex(v), **out})
                    print(f'   copier VM a8={a8:#04x} v={v:#08x}: {out}')

json.dump(res, open('vm_results.json', 'w', encoding='utf8'), ensure_ascii=False, indent=1)
print('\nсохранено vm_results.json')
