"""Воспроизведение выбора имитации и ветки HDR на виртуальном ARM64.
Исходный DAT читается без изменений. Камера и её память не используются.
"""
from pathlib import Path
import csv
import hashlib
import importlib.util
import json
import struct

HERE = Path(__file__).resolve().parent
ROOT = HERE.parent.parent
spec = importlib.util.spec_from_file_location("xh2_base", ROOT / "анализ_файла.py")
base_tools = importlib.util.module_from_spec(spec)
spec.loader.exec_module(base_tools)

from unicorn import Uc, UC_ARCH_ARM64, UC_MODE_ARM, UC_PROT_READ, UC_PROT_EXEC, UC_HOOK_CODE
from unicorn.arm64_const import (
    UC_ARM64_REG_X0, UC_ARM64_REG_X1, UC_ARM64_REG_X2, UC_ARM64_REG_X3,
    UC_ARM64_REG_X19, UC_ARM64_REG_X20, UC_ARM64_REG_X21, UC_ARM64_REG_X22,
    UC_ARM64_REG_X30, UC_ARM64_REG_PC, UC_ARM64_REG_SP,
)

def sha(data):
    return hashlib.sha256(data).hexdigest()

def save_tsv(name, fields, rows):
    with (HERE / name).open("w", encoding="utf-8-sig", newline="") as stream:
        writer = csv.writer(stream, delimiter="\t", lineterminator="\n")
        writer.writerow(fields)
        writer.writerows(rows)

def main():
    raw = base_tools.SOURCE.read_bytes()
    assert sha(raw) == base_tools.EXPECTED_SHA256
    data = raw.translate(base_tools.TRANSLATION)
    a = base_tools.unpack_fflz(data, 0x300274)
    b = base_tools.unpack_fflz(data, 0x840274)
    prior = json.loads((ROOT / "сведения.json").read_text(encoding="utf-8"))
    for off, block in [(0x300274,a),(0x840274,b)]:
        assert sha(block) == next(r["decoded_sha256"] for r in prior["fflz_blocks"] if int(r["file_offset"],16)==off)
    ui = json.loads((HERE.parent / "Доказательства_извлечения.json").read_text(encoding="utf-8"))["film_simulations"]

    template_offset, template_size = 0xc0274, 0xc6c00
    template = data[template_offset:template_offset+template_size]
    assert template[0x100:0x106] == bytes.fromhex("cb0480ff0203")
    assert template[0x106:0x10b] == b"X-H2\0"
    assert template[0x202:0x204] == bytes.fromhex("55aa")
    assert data[template_offset+template_size:template_offset+template_size+256] == bytes([255])*256

    engine = Uc(UC_ARCH_ARM64, UC_MODE_ARM)
    for address, block in [(0x1101000,a),(0x29ae000,b)]:
        length = (len(block)+4095)&~4095
        engine.mem_map(address,length)
        engine.mem_write(address,block)
        engine.mem_protect(address,length,UC_PROT_READ|UC_PROT_EXEC)
    for address,length in [(0x2051000,0x1000),(0x20c1000,0x1000),
        (0x267e000,0x50000),(0x27008000,0x800000),
        (0x60000000,0x20000),(0x70000000,0x10000)]:
        engine.mem_map(address,length)
    engine.mem_write(0x27008000,template)
    engine.mem_write(0x20c1458,struct.pack("<Q",0x27008000))
    stop, params, output = 0x70000000,0x60000000,0x60010000
    argument_regs = [UC_ARM64_REG_X0,UC_ARM64_REG_X1,UC_ARM64_REG_X2,UC_ARM64_REG_X3]
    run_count = 0
    active_boundary = {"address": stop}
    # Обработчик ставится до первого исполнения и остаётся установленным:
    # так граница контролируется и в повторно используемых блоках перевода.
    def stop_at_boundary(uc,address,size,user_data):
        if address==active_boundary["address"]:
            uc.emu_stop()
    engine.hook_add(UC_HOOK_CODE,stop_at_boundary)

    def execute(entry,until=stop):
        nonlocal run_count
        engine.reg_write(UC_ARM64_REG_X30,stop)
        engine.reg_write(UC_ARM64_REG_SP,0x7000fff0)
        active_boundary["address"] = until
        try:
            engine.emu_start(entry,until,timeout=100000,count=10000)
        except Exception:
            print("EMU_FAILURE", hex(entry), hex(until), "pc", hex(engine.reg_read(UC_ARM64_REG_PC)),
                "x19", hex(engine.reg_read(UC_ARM64_REG_X19)), "x20", hex(engine.reg_read(UC_ARM64_REG_X20)), "runs", run_count)
            raise
        assert engine.reg_read(UC_ARM64_REG_PC)==until,hex(entry)
        run_count += 1

    def call(entry,args):
        for reg,value in zip(argument_regs,args+[0]*(4-len(args))):
            engine.reg_write(reg,value)
        execute(entry)
        return engine.reg_read(UC_ARM64_REG_X0)

    def text_at(pointer):
        return bytes(engine.mem_read(pointer,120)).split(b"\0",1)[0].decode("ascii") if pointer else ""

    def translate(parameter,value,source,target):
        engine.mem_write(0x2051408,bytes(4))
        result = call(0x12e67ac,[parameter,value,source,target])
        error = int.from_bytes(engine.mem_read(0x2051408,4),"little")
        return result,error

    root_pointer = 0x1bd5ab8
    table_address = struct.unpack_from("<Q",a,root_pointer-0x1101000+0x68e*8)[0]
    assert table_address == 0x1758bd0
    table_offset = table_address-0x1101000
    raw_rows = [struct.unpack_from("<4I",a,table_offset+i*16) for i in range(26)]
    assert struct.unpack_from("<4I",a,table_offset+26*16)==(0xffff,)*4
    conversions, conversion_checks = [],0
    for index,item in enumerate(ui):
        assert text_at(call(0x117df14,[index]))==item["name"]
        for target in range(5):
            result,error = translate(0x68e,index,0,target)
            expected = index if target==0 else raw_rows[index][target-1]
            if expected==0x7ffffffe:
                assert (result,error)==(0,1)
            else:
                assert (result,error)==(expected,0)
            conversion_checks += 1
        native,error = translate(0x68e,index,0,3)
        native_name = "" if error else text_at(call(0x11437c4,[native]))
        conversions.append({
            "ui_code":index,"ui_name":item["name"],"representations":list(raw_rows[index]),
            "native_code":None if error else native,"native_name":native_name,"error":error,
        })
    for index in [26,100]:
        assert translate(0x68e,index,0,3)==(0,1)
    assert translate(0x6b9,8,0,3)==(8,0)
    assert translate(0x6bb,8,0,3)==(8,0)

    chosen = [(0,"Стандартный",0),(14,"Classic Chrome",13),(18,"ETERNA",18),(17,"REALA",22)]
    stage_rows, hdr_rows = [],[]
    hdr_groups = {}
    for ui_code,name,native in chosen:
        engine.mem_write(params+0x39b8,struct.pack("<I",native))
        engine.mem_write(output,bytes(0x1000))
        engine.reg_write(UC_ARM64_REG_X20,params)
        engine.reg_write(UC_ARM64_REG_X19,output)
        execute(0x2e6276c,0x2e62840)
        packed = int.from_bytes(engine.mem_read(output+0x21d,4),"little")
        assert packed==raw_rows[ui_code][3]

        engine.reg_write(UC_ARM64_REG_X20,params)
        engine.reg_write(UC_ARM64_REG_X19,output)
        engine.reg_write(UC_ARM64_REG_X22,0xffffffff)
        execute(0x2df737c,0x2df73fc)
        group = engine.reg_read(UC_ARM64_REG_X22)
        hdr_groups[name] = group
        assert group=={0:0,13:5,18:7,22:11}[native]

        engine.mem_write(0x2680414,bytes(4))
        call(0x12eefc0,[native])
        assert int.from_bytes(engine.mem_read(0x2680414,4),"little")==native
        stage_rows.append((name,ui_code,native,packed,group))
        frame = params+0x8000
        call(0x1562e18,[frame,native])
        assert int.from_bytes(engine.mem_read(frame+0xc0,4),"little")==native
        cases = [(dr,8,8,"нейтральные_тона") for dr in [2,3,4]]
        cases += [(2,h,8,"изменение_светлых_участков") for h in range(4,17)]
        cases += [(2,8,s,"изменение_тёмных_участков") for s in range(4,17)]
        for dr,h,s,kind in cases:
            engine.mem_write(params,bytes(0x6000))
            engine.mem_write(output,bytes(0x1000))
            for offset,value in [(0x4080,dr),(0x3a90,s),(0x3a8c,h)]:
                engine.mem_write(params+offset,struct.pack("<I",value))
            # Реальный участок переноса параметра из описания кадра в
            # структуру, которую далее читает функция HDR.
            engine.reg_write(UC_ARM64_REG_X21,frame)
            engine.reg_write(UC_ARM64_REG_X20,params)
            execute(0x2e57320,0x2e57330)
            assert int.from_bytes(engine.mem_read(params+0x39b8,4),"little")==native
            call(0x2df72c8,[params,output])
            result = list(engine.mem_read(output+0x114,12))
            assert int.from_bytes(engine.mem_read(output+4,4),"little")==s
            assert int.from_bytes(engine.mem_read(output+12,4),"little")==h
            hdr_rows.append((name,ui_code,native,dr,(h-8)/2,(s-8)/2,kind,*result))
    assert len(hdr_rows)==116
    neutral = {r[0]:list(r[7:]) for r in hdr_rows if r[3]==2 and r[4]==0 and r[5]==0}
    assert neutral["Стандартный"]==[36,63,91,118,160,170,180,190,89,97,170,212]
    assert neutral["Classic Chrome"]==[36,63,91,118,160,170,180,190,112,108,170,212]
    assert neutral["ETERNA"]==[48,71,95,118,160,170,180,190,94,100,170,212]
    assert neutral["REALA"]==neutral["Стандартный"]

    key_rows = []
    key_base = 0x3856a68-0x29ae000
    for outer in range(3):
        for group in range(12):
            for tone in range(9):
                offset = key_base+(outer*108+group*9+tone)*48
                keys = struct.unpack_from("<12I",b,offset)
                assert all(key<len(template) for key in keys)
                values = [template[key] for key in keys]
                key_rows.append((outer,group,tone,hex(offset),*[hex(k) for k in keys],*values))

    save_tsv("Цепочка_выбора.tsv",["имитация","код_интерфейса","код_MODE_FSIM","код_в_пакете_проявки","группа_HDR"],stage_rows)
    save_tsv("Все_преобразования_кодов.tsv",["код_UI","имя_UI","поле_0","поле_1","поле_2_MODE","поле_3","имя_MODE","признак_ошибки"],
        [(r["ui_code"],r["ui_name"],*r["representations"],r["native_name"],r["error"]) for r in conversions])
    save_tsv("HDR_при_разных_настройках.tsv",
        ["имитация","код_UI","код_MODE","DR1_DR2_внутренний_код","светлые_участки","тёмные_участки","тип_проверки"]+[f"B{i}" for i in range(12)],hdr_rows)
    save_tsv("Адреса_и_базовые_значения_HDR.tsv",
        ["внешний_индекс","группа_имитации","тональный_индекс","смещение_в_распакованном_блоке"]+[f"адрес_{i}" for i in range(12)]+[f"значение_{i}" for i in range(12)],key_rows)
    asm = []
    dis = base_tools.Cs(base_tools.CS_ARCH_ARM64,base_tools.CS_MODE_LITTLE_ENDIAN)
    for label,block,base,start,end in [
        ("Преобразование кодов параметра",a,0x1101000,0x12e67ac,0x12e68ec),
        ("Запись MODE_FSIM в состояние",a,0x1101000,0x12eefc0,0x12ef058),
        ("Выбор HDR-группы",b,0x29ae000,0x2df737c,0x2df73fc),
        ("Начало HDR-преобразования",b,0x29ae000,0x2df72c8,0x2df74b8),
        ("Чтение байта настроек",a,0x1101000,0x149ae2c,0x149ae54),
        ("Перенос имитации из кадра в параметры обработки",b,0x29ae000,0x2e57320,0x2e57334),
        ("Ветка копирования базового образа",a,0x1101000,0x149b538,0x149b590),
    ]:
        asm.append("; "+label)
        for address,size,mnemonic,args in dis.disasm_lite(block[start-base:end-base],start):
            asm.append(f"{address:08X}  {mnemonic:8} {args}")
        asm.append("")
    (HERE/"Разобранные_функции.asm").write_text("\n".join(asm),encoding="utf-8")
    proof = {
        "date":"2026-10-31","source":str(base_tools.SOURCE),"source_sha256":sha(raw),
        "module_a_sha256":sha(a),"module_b_sha256":sha(b),
        "bounded_instruction_limit_per_call":10000,"virtual_processor_runs":run_count,
        "conversion_checks_against_raw_table":conversion_checks,
        "template":{"file_offset":hex(template_offset),"size":template_size,"sha256":sha(template),
            "identification":["X-H2 model marker","55 AA signature","exact copy length and following FF padding"],
            "runtime_mapping":"Inferred correspondence to fallback source 0x07500000; actual device contents not read"},
        "addresses":{"conversion_function":"0x12e67ac","conversion_table":"0x1758bd0",
            "native_state_setter":"0x12eefc0","state_field":"0x2680414",
            "hdr_function":"0x2df72c8","hdr_key_table":"0x3856a68",
            "settings_byte_reader":"0x149ae2c","settings_buffer_pointer":"0x20c1458",
            "frame_film_setter":"0x1562e18","frame_to_processing_copy":"0x2e57320",
            "develop_pack_field_offset":"0x21d"},
        "stages":[dict(zip(["name","ui","mode","develop","hdr_group"],r)) for r in stage_rows],
        "neutral_hdr_output":neutral,"hdr_case_count":len(hdr_rows),
        "hdr_key_table_rows":len(key_rows),"input_unchanged":sha(base_tools.SOURCE.read_bytes())==sha(raw),
        "limits":["Baseline template and constructed inputs, not measurements from the camera.",
            "One HDR processing path; not the complete RGB rendering algorithm.",
            "Byte meanings B0..B11 and physical scales are not established.",
            "Other enum representations have not been assigned public protocol names."],
    }
    assert proof["input_unchanged"]
    (HERE/"Проверки_воспроизведения.json").write_text(json.dumps(proof,ensure_ascii=False,indent=2)+"\n",encoding="utf-8")
    print(json.dumps({k:proof[k] for k in ["virtual_processor_runs","conversion_checks_against_raw_table","stages","neutral_hdr_output","hdr_case_count","hdr_key_table_rows","input_unchanged"]},ensure_ascii=True,indent=2))

if __name__=="__main__":
    main()
