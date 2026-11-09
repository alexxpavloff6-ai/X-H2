"""Чтение связей ThreadX/Linux в X-H2 5.30 без запуска файлов камеры."""
from pathlib import Path
import importlib.util
import sys
import struct
import hashlib
import re
import json
import csv

HERE = Path(__file__).resolve().parent
ROOT = HERE.parent
sys.path.insert(0, str(ROOT/'инструменты'))
spec = importlib.util.spec_from_file_location('xh2_distribution_base', ROOT/'анализ_файла.py')
base = importlib.util.module_from_spec(spec)
spec.loader.exec_module(base)
from capstone import Cs, CS_ARCH_ARM64, CS_MODE_ARM


class Image:
    def __init__(self):
        self.raw = base.SOURCE.read_bytes()
        assert hashlib.sha256(self.raw).hexdigest() == base.EXPECTED_SHA256
        self.data = self.raw.translate(base.TRANSLATION)
        self.blocks = [(0x40000, self.data[0x60274:0x60274+0x1E340]),
                       (0x1101000, base.unpack_fflz(self.data, 0x300274)),
                       (0x29AE000, base.unpack_fflz(self.data, 0x840274))]
        self.cs = Cs(CS_ARCH_ARM64, CS_MODE_ARM)

    def read(self, address, size):
        for start, data in self.blocks:
            if start <= address and address+size <= start+len(data):
                return data[address-start:address-start+size]
        return None

    def string(self, address):
        if address is None:
            return None
        b = self.read(address, 128)
        if not b:
            return None
        b = b.split(b'\0', 1)[0]
        if not b or not all(32 <= c < 127 for c in b):
            return None
        return b.decode('ascii')

    def instructions(self, start, end):
        data = self.read(start, end-start)
        assert data is not None
        return list(self.cs.disasm_lite(data, start))

    def calls(self, targets):
        results = []
        for start, data in self.blocks:
            for off in range(0, len(data)-3, 4):
                w = struct.unpack_from('<I', data, off)[0]
                if w & 0xFC000000 != 0x94000000:
                    continue
                delta = w & 0x3FFFFFF
                if delta & (1 << 25):
                    delta -= 1 << 26
                target = start+off+delta*4
                if target in targets:
                    results.append((start+off, target))
        return results


def task_argument(image, call):
    """Ограниченное распространение констант перед вызовом, без исполнения ветвей.

    Результат является кандидатом: реальную достижимость ветви это не доказывает.
    Неизвестные входы остаются неизвестными; им не назначаются выдуманные числа.
    """
    regs = {'sp': 0x7000F000}
    memory = {}

    def get(r):
        if r in ('wzr', 'xzr'):
            return 0
        if r == 'sp':
            return regs['sp']
        v = regs.get('x'+r[1:])
        return v & 0xFFFFFFFF if v is not None and r.startswith('w') else v

    def put(r, value):
        if r == 'sp':
            return
        if r in ('wzr', 'xzr'):
            return
        regs['x'+r[1:]] = None if value is None else value & ((1 << (32 if r[0] == 'w' else 64))-1)

    def store(address, size, value):
        for j in range(size):
            memory[address+j] = None if value is None else (value >> (8*j)) & 255

    def load(address, size):
        if any(address+j in memory for j in range(size)):
            b = [memory.get(address+j) for j in range(size)]
            return None if any(v is None for v in b) else int.from_bytes(bytes(b), 'little')
        b = image.read(address, size)
        return int.from_bytes(b, 'little') if b is not None else None

    for addr, size, op, operands in image.instructions(call-192, call):
        if op == 'ret':
            regs = {'sp': 0x7000F000}
            memory.clear()
            continue
        if op in ('bl', 'blr'):
            for j in range(19):
                regs['x'+str(j)] = None
            continue
        m = re.fullmatch(r'(x\d+), #(0x[0-9a-f]+)', operands)
        if op in ('adrp', 'adr') and m:
            put(m[1], int(m[2], 0))
            continue
        m = re.fullmatch(r'([wx]\d+), ([wx]\d+|[wx]zr|sp|#-?(?:0x[0-9a-f]+|\d+))', operands)
        if op == 'mov' and m:
            put(m[1], int(m[2][1:], 0) if m[2].startswith('#') else get(m[2]))
            continue
        m = re.fullmatch(r'([wx]\d+), ([wx]\d+|sp), #(-?(?:0x[0-9a-f]+|\d+))(?:, lsl #(\d+))?', operands)
        if op in ('add', 'sub') and m:
            v = get(m[2])
            n = int(m[3], 0) << int(m[4] or 0)
            put(m[1], None if v is None else v + (n if op == 'add' else -n))
            continue
        m = re.fullmatch(r'([wx]\d+|[wx]zr), \[(sp|x\d+)(?:, #(-?(?:0x[0-9a-f]+|\d+)))?\]', operands)
        if op in ('str', 'stur', 'strh', 'strb', 'ldr', 'ldur', 'ldrh', 'ldrb', 'ldrsw') and m:
            address = get(m[2])
            address = None if address is None else address+int(m[3] or '0', 0)
            n = 1 if op.endswith('b') else 2 if op.endswith('h') else 8 if m[1].startswith('x') else 4
            if op == 'ldrsw':
                n = 4
            if op.startswith(('str', 'stu')):
                if address is not None:
                    store(address, n, get(m[1]))
            else:
                put(m[1], None if address is None else load(address, n))
            continue
        # Остальные записи в регистр считаются неизвестными, а не игнорируются.
        if op not in ('cmp', 'cmn', 'tst', 'b', 'b.eq', 'b.ne', 'b.hi', 'b.ls', 'cbz', 'cbnz',
                      'tbz', 'tbnz', 'str', 'strb', 'strh', 'stp', 'nop'):
            dest = operands.split(',', 1)[0]
            if re.fullmatch(r'[wx]\d+', dest):
                put(dest, None)
    pointer = get('x0')
    argument_registers = {f'x{j}': get(f'x{j}') for j in range(4)}
    register_values = {str(j): get(f'x{j}') for j in range(31)}
    if pointer is None:
        return {'call': hex(call), 'resolved': False, 'argument_registers': argument_registers,
                'register_values': register_values}
    values = {name: load(pointer+off, size) for name, off, size in [
        ('id', 0, 4), ('name_pointer', 8, 8), ('priority', 16, 4),
        ('stack_bytes', 20, 4), ('entry', 24, 8), ('argument', 32, 8)]}
    values['name'] = image.string(values['name_pointer'])
    return {'call': hex(call), 'resolved': values['name'] is not None,
            **values, 'argument_registers': argument_registers,
            'register_values': register_values,
            'method': 'constant propagation; branch reachability not established'}


def main():
    image = Image()
    refs = image.calls({0x14CE004})
    rows = [task_argument(image, call) for call, target in refs]
    for row in rows:
        if row.get('name'):
            print(row['call'], row.get('id'), row['name'], row.get('priority'),
                  hex(row['stack_bytes']) if row.get('stack_bytes') is not None else None,
                  hex(row['entry']) if row.get('entry') is not None else None)
    print('TOTAL', len(rows), 'NAMED', sum(bool(r.get('name')) for r in rows))
    (HERE/'Кандидаты_задач_ThreadX.json').write_text(
        json.dumps({'source_sha256': hashlib.sha256(image.raw).hexdigest(),
                    'creator': '0x014CE004', 'candidates': rows}, ensure_ascii=False, indent=2)+'\n', encoding='utf-8')
    with (HERE/'Кандидаты_задач_ThreadX.tsv').open('w', encoding='utf-8-sig', newline='') as f:
        fields = ['call', 'id', 'name', 'priority', 'stack_bytes', 'entry', 'argument', 'resolved']
        w = csv.DictWriter(f, fieldnames=fields, delimiter='\t', extrasaction='ignore', lineterminator='\n')
        w.writeheader()
        w.writerows(rows)


if __name__ == '__main__':
    main()
