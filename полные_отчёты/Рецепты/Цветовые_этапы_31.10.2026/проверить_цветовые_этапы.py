"""Чтение и ограниченное воспроизведение цветовых ветвей X-H2 5.30.

Все исходные машинные команды исполняются без исправлений в виртуальном ARM64.
Данные испытаний искусственные; память реальной камеры не читается.
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
base = importlib.util.module_from_spec(spec)
spec.loader.exec_module(base)
from unicorn import Uc, UC_ARCH_ARM64, UC_MODE_ARM, UC_PROT_READ, UC_PROT_EXEC, UC_HOOK_CODE
from unicorn.arm64_const import *

def sha(data):
    return hashlib.sha256(data).hexdigest()

def tsv(name, fields, rows):
    with (HERE / name).open("w", encoding="utf-8-sig", newline="") as stream:
        writer = csv.writer(stream, delimiter="\t", lineterminator="\n")
        writer.writerow(fields)
        writer.writerows(rows)

class Study:
    def __init__(self):
        self.raw = base.SOURCE.read_bytes()
        assert sha(self.raw) == base.EXPECTED_SHA256
        self.data = self.raw.translate(base.TRANSLATION)
        self.a = base.unpack_fflz(self.data, 0x300274)
        self.b = base.unpack_fflz(self.data, 0x840274)
        self.low = self.data[0x60274:0x60274+0x1e340]
        self.template = self.data[0xc0274:0xc0274+0xc6c00]
        self.uc = Uc(UC_ARCH_ARM64, UC_MODE_ARM)
        for address, block in [(0x1101000,self.a),(0x29ae000,self.b),(0x40000,self.low)]:
            size = (len(block)+4095)&~4095
            self.uc.mem_map(address,size)
            self.uc.mem_write(address,block)
            self.uc.mem_protect(address,size,UC_PROT_READ|UC_PROT_EXEC)
        for address,size in [(0x2051000,0x1000),(0x20c1000,0x1000),
            (0x27008000,0x800000),(0x60000000,0x40000),(0x70000000,0x10000),
            (0xff000000,0x1000)]:
            self.uc.mem_map(address,size)
        self.uc.mem_write(0x27008000,self.template)
        self.uc.mem_write(0x20c1458,struct.pack("<Q",0x27008000))
        self.stop = 0x70000000
        self.boundary = self.stop
        self.runs = []
        self.reads = []
        self.blends = []
        self.uc.hook_add(UC_HOOK_CODE,self.hook)

    def hook(self,uc,address,size,user):
        if address == self.boundary:
            uc.emu_stop()
        elif address == 0x149ae2c:
            self.reads.append(uc.reg_read(UC_ARM64_REG_X0)&0xffffffff)
        elif address == 0x2f229f4:
            values=[uc.reg_read(globals()[f"UC_ARM64_REG_X{j}"]) for j in range(8)]
            self.blends.append({"shadow":values[0]&0xffffffff,"highlight":values[1]&0xffffffff,
                "split":values[6]&255,"arrays":[list(struct.unpack("<40H",uc.mem_read(pointer,80))) for pointer in values[2:6]]})

    def reg(self,number,value):
        self.uc.reg_write(globals()[f"UC_ARM64_REG_X{number}"],value)

    def word(self,address,value):
        self.uc.mem_write(address,struct.pack("<I",value&0xffffffff))

    def u32(self,address):
        return struct.unpack("<I",self.uc.mem_read(address,4))[0]

    def clear(self,address,size=0x1000):
        self.uc.mem_write(address,bytes(size))

    def run(self,entry,args=(),until=None,registers=None):
        until = self.stop if until is None else until
        self.reads = []
        self.blends = []
        for number in range(8):
            self.reg(number,args[number] if number<len(args) else 0)
        for number,value in (registers or {}).items():
            self.reg(number,value)
        self.reg(30,self.stop)
        # Запас сверху нужен также фрагментам, начинающимся после пролога.
        self.uc.reg_write(UC_ARM64_REG_SP,0x7000f000)
        self.boundary = until
        try:
            self.uc.emu_start(entry,until,timeout=500000,count=200000)
        except Exception as error:
            raise RuntimeError(f"{entry:#x}: PC={self.uc.reg_read(UC_ARM64_REG_PC):#x}; {error}") from error
        assert self.uc.reg_read(UC_ARM64_REG_PC)==until,hex(entry)
        self.runs.append({"entry":hex(entry),"until":hex(until),"settings_reads":[hex(k) for k in self.reads]})
        return self.uc.reg_read(UC_ARM64_REG_X0)

    def keys(self,address,count):
        return struct.unpack_from("<"+str(count)+"I",self.b,address-0x29ae000)

def main():
    x = Study()
    p,o,q = 0x60000000,0x60010000,0x60020000
    modes = [("STANDARD",0),("F1b",1),("F2",3),("PRO_NEG_1",11),
             ("PRO_NEG_2",12),("CLASSIC_CHROME",13),("ETERNA",18),
             ("SUPERIA",19),("BLEACH",20),("AMERICAN_NEW_COLOR",21),("REALA",22)]
    rows=[]
    details=[]
    for name,mode in modes:
        x.clear(p)
        x.run(0x2f38c30,[p,mode])
        color_mode = x.u32(p)
        # Ровно тот перенос MODE -> поле 0x130, который делает 0x2F39D80.
        x.clear(p)
        x.word(o+0x20,mode)
        x.run(0x2f39e64,until=0x2f39e70,registers={19:p,20:o})
        assert x.u32(p+0x130)==color_mode
        x.word(p+0x12c,1)  # В основной функции устанавливается безусловно.
        x.word(p+0x124,0x12)
        x.word(p+0x128,0x12)
        x.word(p+0x13c,4)  # Испытательное среднее положение; шкала отдельно не назначается.
        x.word(p+0x10c,8)
        x.word(p+0x17c,2)
        x.word(p+0x180,0)
        x.clear(o)
        x.run(0x2f24284,[p,o])
        selector = bytes(x.uc.mem_read(o,1))[0]
        selector_reads=list(x.reads)
        x.clear(o)
        x.run(0x2f24680,[p,o])
        matrix_out = list(struct.unpack("<6H",x.uc.mem_read(o+0x3c,12)))
        matrix_reads=list(x.reads)
        # Точно та же структура из четырёх слов, которую собирает 0x2F38304.
        x.uc.mem_write(q,struct.pack("<4I",0,1,color_mode,0))
        three_d = x.run(0x2f2926c,[q])&255
        three_d_reads=list(x.reads)
        x.uc.mem_write(q,struct.pack("<4I",0,1,color_mode,0))
        three_d_enabled = x.run(0x2f29964,[q,0])
        assert bool(three_d_enabled)==bool(three_d)
        rows.append((name,mode,color_mode,selector,three_d,three_d_enabled,*matrix_out))
        details.append({"name":name,"mode":mode,"color_mode":color_mode,
            "coefficient_selector":selector,"coefficient_selector_reads":[hex(k) for k in selector_reads],
            "output_halfwords_3c_46":matrix_out,"coefficient_reads":[hex(k) for k in matrix_reads],
            "additional_3d_selector":three_d,"additional_3d_reads":[hex(k) for k in three_d_reads],
            "constructed_context":True})
    assert next(r for r in rows if r[0]=="CLASSIC_CHROME")[2:6]==(8,6,0,0)
    tsv("Выбор_цветовых_ветвей.tsv",["имитация_MODE","код_MODE","код_цветового_блока",
        "селектор_четырёх_коэффициентов","селектор_дополнительной_3D_таблицы","3D_включена"]+
        ["слово_"+hex(k) for k in range(0x3c,0x48,2)],rows)

    coefficients=[]
    for name,mode,color_mode,selector,*rest in rows:
        keys=x.keys(0x3438c80+(selector-1)*16,4)
        values=[struct.unpack_from("<H",x.template,key)[0] for key in keys]
        coefficients.append((name,selector,*[hex(k) for k in keys],*values))
    tsv("Четыре_исходных_коэффициента.tsv",["имитация","селектор"]+
        [f"адрес_{j}" for j in range(4)]+[f"u16_{j}" for j in range(4)],coefficients)

    def signed13(value):
        value &= 0x1fff
        return value-0x2000 if value&0x1000 else value

    cc=next(row for row in coefficients if row[0]=="CLASSIC_CHROME")
    decoded=[signed13(v) for v in cc[6:10]]
    assert decoded==[885,859,-10,-12]
    # Матрица в порядке строк: a,b,c,d. Исходная таблица хранит a,d,b,c.
    matrix=[decoded[0],decoded[2],decoded[3],decoded[1]]
    assert matrix==[885,-10,-12,859]
    color_rows=[]
    for native in range(9):
        x.clear(p)
        x.clear(o)
        x.run(0x2f390bc,[o,native,1,0])
        color_index=x.u32(o)
        assert color_index==8-native
        x.word(p+0x12c,1)
        x.word(p+0x130,8)
        x.word(p+0x124,0x12)
        x.word(p+0x128,0x12)
        x.word(p+0x13c,color_index)
        x.word(p+0x10c,8)
        x.word(p+0x17c,2)
        x.run(0x2f24680,[p,o])
        actual=struct.unpack("<4h",x.uc.mem_read(o+0x3c,8))
        gain=x.template[0xaf50+color_index]
        # Три множителя в 0x2F247D0..0x2F248BC. Остальные два здесь равны 128 и 64.
        expected=tuple(max(-4096,min(4095,(value*gain*128*64)>>20)) for value in [885,-10,859,-12])
        assert actual==expected,(native,actual,expected)
        # Последнее представление параметра 0x6B3 содержит +40..-40; единица интерфейса = 10.
        representation=struct.unpack_from("<i",x.a,0x176d7b0-0x1101000+native*16+12)[0]
        color_rows.append((representation//10,native,color_index,gain,128,64,gain/128,*actual))
    tsv("Classic_Chrome_пункт_Цвет.tsv",["значение_Цвет","внутреннее_значение","индекс_таблицы",
        "множитель_Цвет","дополнительный_множитель_1","дополнительный_множитель_2","отношение_к_Цвет_0",
        "слово_3c","слово_3e","слово_40","слово_42"],color_rows)

    tone_rows=[]
    tone_proof=[]
    weights=list(x.b[0x3438948-0x29ae000:0x3438948-0x29ae000+17])
    for value in range(4,17):
        x.clear(p)
        x.clear(o)
        x.word(p+0x12c,1)
        x.word(o+0x30,value)
        x.word(o+0x34,value)
        x.run(0x2f39ea4,until=0x2f39ecc,registers={19:p,20:o})
        assert x.u32(p+0x114)==value and x.u32(p+0x118)==value
    tone_pairs=[(8,8)]+[(j,8) for j in range(4,17) if j!=8]+[(8,j) for j in range(4,17) if j!=8]
    for name,mode in [("STANDARD",0),("CLASSIC_CHROME",13),("ETERNA",18),("REALA",22)]:
        x.clear(p)
        x.run(0x2f38c30,[p,mode])
        color_mode=x.u32(p)
        for highlight,shadow in tone_pairs:
            x.clear(p)
            x.clear(o)
            x.clear(q)
            x.word(p+0x12c,1)
            x.word(p+0x130,color_mode)
            x.word(p+0x114,highlight)
            x.word(p+0x118,shadow)
            # Отдельно исследуется основная ветвь с нулевым вспомогательным описателем.
            # Это явно заданные входы, а не снимок всех параметров камеры.
            x.run(0x2f22acc,[p,q,o])
            values=list(struct.unpack("<40H",x.uc.mem_read(o,80)))
            assert len(x.blends)==1
            blend=x.blends[0]
            expected=[]
            for j in range(40):
                first,second,position=(0,1,shadow) if j<blend["split"] else (2,3,highlight)
                av,bv=blend["arrays"][first][j],blend["arrays"][second][j]
                delta=(bv-av)*weights[position]
                rounded=(delta+(64 if delta+64>=0 else 191))>>7
                expected.append(min(65535,av+rounded)&65535)
            assert values==expected,(name,highlight,shadow)
            tone_rows.append((name,(highlight-8)/2,(shadow-8)/2,highlight,shadow,blend["split"],*values))
            tone_proof.append({"name":name,"highlight":highlight,"shadow":shadow,
                "settings_reads":[hex(k) for k in x.reads],"blend":blend,"output":values})
    tsv("Тональные_таблицы_40_значений.tsv",["имитация","светлые_участки","тёмные_участки",
        "внутренний_H","внутренний_S","граница_участков"]+[f"узел_{j}" for j in range(40)],tone_rows)
    assert len(tone_rows)==100
    cc_tone=next(row[6:] for row in tone_rows if row[:3]==("CLASSIC_CHROME",0,0))
    assert cc_tone[:4]==(402,404,406,409) and cc_tone[-1]==512

    # Проверка расширения 12 HDR-байтов в 16-разрядные поля задания.
    prior= json.loads((HERE.parent/"Трассировка_31.10.2026"/"Проверки_воспроизведения.json").read_text(encoding="utf-8"))
    hdr = prior["neutral_hdr_output"]["Classic Chrome"]
    if isinstance(hdr,dict):
        raise AssertionError("Изменилась схема предыдущего отчёта")
    x.clear(p)
    x.uc.mem_write(p+0x114,bytes(hdr))
    for address,ptr,width in [(q,0x61000000,4096),(q+0x80,0x62000000,2048)]:
        x.clear(address,0x80)
        x.word(address+8,ptr)
        x.word(address+0x20,2048)
        x.word(address+0x24,width)
        x.word(address+0x28,1000)
    x.run(0x2e002d8,until=0x2e003b4,registers={19:p,20:q,21:q+0x80})
    sp=x.uc.reg_read(UC_ARM64_REG_SP)
    task=bytes(x.uc.mem_read(sp+0x38,0x38))
    expanded=list(struct.unpack_from("<12H",task,0xc))
    assert expanded==hdr
    (HERE/"Задание_HDRCR_Classic_Chrome.bin").write_bytes(task)
    assert x.low[0x5de10-0x40000:0x5de18-0x40000] == bytes.fromhex("010000b9c0035fd6")
    # Виртуальная страница изображает область регистров, а не аппаратное устройство.
    # Проверяются только адреса и передача слов; вычисление изображения не имитируется.
    x.uc.mem_write(q,task)
    x.uc.mem_write(0xff000000,bytes([0xa5])*4096)
    x.run(0x138c3c0,[q,0x2c])
    register_bytes=bytes(x.uc.mem_read(0xff000040,0x2c))
    assert register_bytes==task[:0x2c]
    assert bytes(x.uc.mem_read(0xff00006c,4))==bytes([0xa5])*4
    register_rows=[]
    for j,value in enumerate(hdr):
        assert struct.unpack_from("<H",register_bytes,0xc+j*2)[0]==value
        register_rows.append((f"B{j}",hex(0x114+j),hex(0xc+j*2),hex(0xff00004c+j*2),value))
    tsv("Путь_12_параметров_HDR.tsv",["параметр","смещение_в_блоке_HDR","смещение_в_задании",
        "виртуальный_адрес_регистра","значение"],register_rows)
    exif=[]
    for mode,expected in [(0,0),(13,0x600),(18,0x700),(22,0xb00)]:
        x.clear(p,0x8000)
        x.word(p+0x3978,2)
        x.word(p+0x39b8,mode)
        result=x.run(0x2e516fc,[p])
        assert result==expected,(mode,result,expected)
        exif.append({"mode":mode,"metadata_code":hex(result)})

    asm=[]
    for label,start,end in [
        ("MODE в код цветового блока",0x2f38c30,0x2f38ce8),
        ("Перенос кода в параметры обработки",0x2f39e50,0x2f39efc),
        ("Выбор четырёх коэффициентов",0x2f24284,0x2f243c8),
        ("Сборка блока коэффициентов",0x2f24680,0x2f248c0),
        ("Преобразование пункта Цвет",0x2f390bc,0x2f3916c),
        ("Выбор тональной таблицы",0x2f22388,0x2f226b8),
        ("Интерполяция тональных таблиц",0x2f22720,0x2f22bec),
        ("Параметры отдельной 3D-ветви",0x2dea3b8,0x2dea41c),
        ("Нормализация входа 3D-ветви",0x2f382a4,0x2f38304),
        ("Выбор дополнительной 3D-таблицы",0x2f2926c,0x2f29328),
        ("Диспетчер HDRCR",0x2e00298,0x2e0043c),
        ("Контроль HDR",0x2df72c8,0x2df78cc),
        ("Параметры HDRCR",0x138b6a0,0x138b710),
        ("Запись задания в регистры",0x138bf00,0x138bf5c),
        ("Обёртка записи задания",0x138c3c0,0x138c3dc),
        ("Отдельный код для метаданных",0x2e516fc,0x2e51910),
        ("Прямая запись/чтение регистра",0x5de10,0x5de50),
    ]:
        block,address=(x.low,0x40000) if start<0x100000 else ((x.a,0x1101000) if start<0x2000000 else (x.b,0x29ae000))
        asm.append("; "+label)
        md=base.Cs(base.CS_ARCH_ARM64,base.CS_MODE_LITTLE_ENDIAN)
        for va,size,mnemonic,args in md.disasm_lite(block[start-address:end-address],start):
            asm.append(f"{va:08X}  {mnemonic:8} {args}")
        asm.append("")
    (HERE/"Разобранные_цветовые_ветви.asm").write_text("\n".join(asm),encoding="utf-8")
    proof={"source":str(base.SOURCE),"source_sha256":sha(x.raw),"module_a_sha256":sha(x.a),
        "module_b_sha256":sha(x.b),"template_sha256":sha(x.template),
        "virtual_runs":len(x.runs),"instruction_limit_per_run":200000,
        "real_camera_accessed":False,"firmware_modified":False,
        "color_branches":details,"hdr_input_bytes":hdr,"hdr_task_halfwords":expanded,
        "classic_chrome_matrix_signed":matrix,"classic_chrome_matrix_divisor":1024,
        "color_control_cases":len(color_rows),"color_matrix_formula_checks":len(color_rows),
        "tone_table_cases":len(tone_rows),"tone_interpolation_checks":len(tone_rows)*40,
        "tone_context":"P+0x12C=1; P+0x130=converted mode; P+0x114/118=H/S; auxiliary descriptor is zero; all other fields zero",
        "tone_weights_128ths":weights,"tone_details":tone_proof,
        "hdr_register_transfer_verified":True,"hdr_register_emulation":"Plain virtual RAM; no hardware algorithm or pixel processing emulated",
        "metadata_codes":exif,
        "hdr_task_sha256":sha(task),"calls":x.runs,
        "input_unchanged":sha(base.SOURCE.read_bytes())==sha(x.raw)}
    assert proof["input_unchanged"]
    (HERE/"Проверки_цветовых_ветвей.json").write_text(json.dumps(proof,ensure_ascii=False,indent=2)+"\n",encoding="utf-8")
    print(json.dumps({"runs":len(x.runs),"branches":rows,"hdr_zero_extension_verified":True,
                      "color_formula_checks":len(color_rows),"tone_node_checks":len(tone_rows)*40,
                      "input_unchanged":proof["input_unchanged"]},ensure_ascii=True,indent=2))

if __name__=="__main__":
    main()
