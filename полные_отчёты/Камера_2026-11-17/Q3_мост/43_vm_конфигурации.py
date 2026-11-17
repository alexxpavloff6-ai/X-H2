# -*- coding: utf-8 -*-
"""Q3 3-й круг, шаг 43: Unicorn-оценщик 0x30308A0 и предикат 0x2FE35D4 на входах
реальных конфигураций. fieldB = знаменатель/100 (из speed_output 0x18C), shutter_type
= фактический затвор (0x1A8), fieldA = гейт CH+CONTINUOUS. Таблица 0x3456B20 в(block1)."""
import json
import sys
from pathlib import Path

HERE = Path(__file__).resolve().parent
sys.path.insert(0, str(HERE))
from q3common import load  # noqa: E402
from unicorn import Uc, UC_ARCH_ARM64, UC_MODE_LITTLE_ENDIAN, UC_HOOK_CODE  # noqa: E402
from unicorn.arm64_const import (UC_ARM64_REG_PC, UC_ARM64_REG_SP, UC_ARM64_REG_LR,  # noqa: E402
                                 UC_ARM64_REG_X0, UC_ARM64_REG_X1, UC_ARM64_REG_X2,
                                 UC_ARM64_REG_X3, UC_ARM64_REG_X4, UC_ARM64_REG_X5)

b0 = load('X-H2', 'old', 0)
b1 = load('X-H2', 'old', 1)
inputs = json.loads((HERE / '3круг_входы_снимков.json').read_text(encoding='utf-8'))


def pagesz(n):
    return (n + 0xFFF) & ~0xFFF


def make_mu():
    mu = Uc(UC_ARCH_ARM64, UC_MODE_LITTLE_ENDIAN)
    mu.mem_map(b0.base, pagesz(len(b0.data)))
    mu.mem_write(b0.base, b0.data)
    mu.mem_map(b1.base, pagesz(len(b1.data)))
    mu.mem_write(b1.base, b1.data)
    mu.mem_map(0x4D35000, 0x1000)      # ctx 0x4D35708
    mu.mem_map(0x4DBB000, 0x1000)      # [0x4DBB400] mode
    mu.mem_map(0x10000000, 0x10000)    # stack
    mu.reg_write(UC_ARM64_REG_SP, 0x10008000)
    return mu


def eval_30308a0(fieldA, shutter_type, fieldB, drive):
    """0x30308A0(w0=fieldA, w1=shutter_type, w2=fieldB, w3=getter3, w4=drive, w5=getter5)."""
    mu = make_mu()
    mu.reg_write(UC_ARM64_REG_X0, fieldA)
    mu.reg_write(UC_ARM64_REG_X1, shutter_type)
    mu.reg_write(UC_ARM64_REG_X2, fieldB)
    mu.reg_write(UC_ARM64_REG_X3, 0)        # getter3
    mu.reg_write(UC_ARM64_REG_X4, drive)    # getter4
    mu.reg_write(UC_ARM64_REG_X5, 0)        # getter5
    mu.reg_write(UC_ARM64_REG_LR, 0x10000000)
    mu.emu_start(0x30308A0, 0x10000000, count=300)
    return mu.reg_read(UC_ARM64_REG_X0) & 0xFFFFFFFF


def predicate_2fe35d4(ctx_flags, eval_result):
    """0x2FE35D4: гейты по ctx [0x4D35710]; hook 0x30256EC -> eval_result."""
    mu = make_mu()
    mu.mem_write(0x4D35710, ctx_flags.to_bytes(4, 'little'))
    mu.mem_write(0x4DBB400, (0x1D).to_bytes(4, 'little'))
    state = {'ret': eval_result}

    def hook(mu, addr, size, user):
        if addr == 0x30256EC:           # подменяем оценщик known-результатом
            mu.reg_write(UC_ARM64_REG_X0, state['ret'])
            mu.reg_write(UC_ARM64_REG_PC, mu.reg_read(UC_ARM64_REG_LR))
        elif addr == 0x2FD8DBC:         # ctx getter -> 0x4D35708
            mu.reg_write(UC_ARM64_REG_X0, 0x4D35708)
            mu.reg_write(UC_ARM64_REG_PC, mu.reg_read(UC_ARM64_REG_LR))
    mu.hook_add(UC_HOOK_CODE, hook)
    mu.reg_write(UC_ARM64_REG_LR, 0x10000000)
    mu.emu_start(0x2FE35D4, 0x10000000, count=300)
    return mu.reg_read(UC_ARM64_REG_X0) & 0xFFFFFFFF


rows = []
for r in inputs:
    sp = r['speed_output'] or 0
    fieldB = sp // 10000                 # знаменатель/100
    shutter_type = r['shutter_actual']   # фактический затвор (0 MS,1 ES,3 EF)
    ch = (r['drive_ch'] == 21)
    cont = (r['rec_view'] == 2)
    fieldA = 1 if (ch and cont) else 0   # гейт CH+CONTINUOUS (К)
    drive = 4 if ch else 0               # getter4 ∈{3,4} для CH (К)
    flag_eval = eval_30308a0(fieldA, shutter_type, fieldB, drive)
    # предикат с гейтами ctx=0 (проходят) и с установленным bit12 (блокирует)
    pred_pass = predicate_2fe35d4(0x00000000, flag_eval)
    pred_block = predicate_2fe35d4(0x00001000, flag_eval)   # bit12 -> 0
    rows.append({
        'label': r['label'], 'shutter_menu': r['shutter_menu_label'],
        'shutter_actual': r['shutter_actual_label'], 'shutter_type_input': shutter_type,
        'drive_ch': ch, 'rec_view': r['rec_view'], 'continuous_display': cont,
        'speed': r['speed_text'], 'speed_output_18C': sp, 'speed_m_index_5B2': r['speed_m_index'],
        'fieldB_denom_div100': fieldB, 'fieldA_gate': fieldA, 'drive_input': drive,
        'flag_eval_30308A0': flag_eval, 'predicate_ctx0': pred_pass, 'predicate_bit12': pred_block,
        'defect_backup': r['defect_backup'],
    })

# проверка гейтов предиката отдельно (bit4/12/13/14)
gate_tests = {}
for name, flags in (('ctx0', 0), ('bit4', 0x10), ('bit12', 0x1000), ('bit13', 0x2000), ('bit14', 0x4000)):
    gate_tests[name] = predicate_2fe35d4(flags, 1)

result = {'configurations': rows, 'predicate_gate_tests_eval1': gate_tests,
          'note_fieldB': 'fieldB = знаменатель выдержки / 100 = speed_output(0x18C)//10000; категории таблицы кодировщика 0x14F396C точно совпадают (Д для значений, К для семантики)',
          'note_fieldA': 'fieldA = гейт CH(0x68C==21) + IMAGE DISP CONTINUOUS(0x29B==2); писатель struct+0xCC не прослежен полностью (К)',
          'note_shutter': 'shutter_type = фактический затвор 0x1A8 (0 MS,1 ES,2 MS+ES,3 EF); для MS+ES на быстрой выдержке факт=ES=1'}
(HERE / '3круг_vm_конфигурации.json').write_text(json.dumps(result, ensure_ascii=False, indent=2) + '\n', encoding='utf-8')

print('label | menu | actual | st_in | CH | CONT | speed | fieldB | fieldA | flag_eval | pred_ctx0 | pred_bit12 | defectBACKUP')
for r in rows:
    print(' | '.join(str(x) for x in [r['label'], r['shutter_menu'], r['shutter_actual'], r['shutter_type_input'],
                                      r['drive_ch'], r['continuous_display'], r['speed'], r['fieldB_denom_div100'],
                                      r['fieldA_gate'], r['flag_eval_30308A0'], r['predicate_ctx0'], r['predicate_bit12'],
                                      r['defect_backup']]))
print('\nгейты предиката (eval=1):', gate_tests)
