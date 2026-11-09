"""Дополнительные проверки для отчёта с указателями на изображении.

Исходный DAT не изменяется. Путь WB проверяется до внутренних кодов;
преобразование этих кодов в окончательные RGB-пиксели не приписывается тесту.
"""
from pathlib import Path
import importlib.util
import json
import struct

HERE=Path(__file__).resolve().parent
spec=importlib.util.spec_from_file_location("color_study",HERE/"проверить_цветовые_этапы.py")
study=importlib.util.module_from_spec(spec)
spec.loader.exec_module(study)

def main():
    x=study.Study()
    p,o=0x60000000,0x60010000
    mode_names=["UI_WB_AUTO","UI_WB_AUTO_WHITE","UI_WB_AUTO_ATMOSPHERE",
        "UI_WB_CUSTOM1","UI_WB_CUSTOM2","UI_WB_CUSTOM3","UI_WB_KELVIN",
        "UI_WB_CLEAR","UI_WB_CLOUDY","UI_WB_F_LAMP1","UI_WB_F_LAMP2",
        "UI_WB_F_LAMP3","UI_WB_BULB","UI_WB_UNDERWATER"]
    expected=[0,1,2,10,11,12,13,3,4,5,6,7,8,9]
    wb=[]
    for ui,(name,wanted) in enumerate(zip(mode_names,expected)):
        x.word(0x2051408,0)
        result=x.run(0x12e67ac,[0x5f5,ui,0,3])&0xffffffff
        assert result==wanted and x.u32(0x2051408)==0,(ui,result,wanted)
        wb.append({"ui_code":ui,"ui_name":name,"native_code":result})
    shifts=[]
    for axis,param in [("R",0x6bf),("B",0x6dd)]:
        for ui in range(19):
            x.word(0x2051408,0)
            result=x.run(0x12e67ac,[param,ui,0,3])&0xffffffff
            signed=result if result<0x80000000 else result-0x100000000
            assert signed==9-ui and x.u32(0x2051408)==0
            x.clear(o)
            x.run(0x2e62290,[result,o])
            packed=struct.unpack("<i",x.uc.mem_read(o,4))[0]
            assert packed==signed
            shifts.append({"axis":axis,"parameter":hex(param),"ui_code":ui,
                "native_value":signed,"develop_pack_value":packed})
    # Конкретные контрольные примеры для меток 3–5.
    old=json.loads((HERE/"Проверки_цветовых_ветвей.json").read_text(encoding="utf-8"))
    cases={}
    for label,h,s in [("neutral",8,8),("highlight_plus_2",12,8),("shadow_plus_2",8,12)]:
        wanted=next(z for z in old["tone_details"] if z["name"]=="CLASSIC_CHROME" and z["highlight"]==h and z["shadow"]==s)
        x.clear(p);x.clear(o);x.clear(0x60020000)
        for offset,value in [(0x12c,1),(0x130,8),(0x114,h),(0x118,s)]:x.word(p+offset,value)
        x.run(0x2f22acc,[p,0x60020000,o])
        result=list(struct.unpack("<40H",x.uc.mem_read(o,80)))
        assert result==wanted["output"]
        cases[label]={"H_internal":h,"S_internal":s,"output":result}
    neutral=cases["neutral"]["output"]
    for label in ["highlight_plus_2","shadow_plus_2"]:
        cases[label]["changed_indices"]=[i for i,(av,bv) in enumerate(zip(neutral,cases[label]["output"])) if av!=bv]
    assert cases["highlight_plus_2"]["changed_indices"]==list(range(27,39))
    assert cases["shadow_plus_2"]["changed_indices"]==list(range(27))
    # Воспроизведение полученных коэффициентов Classic Chrome при «Цвет» 0 и +2.
    color=[]
    for display,native,index,gain,wanted in [(0,4,4,128,[885,-10,859,-12]),(2,2,6,141,[974,-12,946,-14])]:
        x.clear(p);x.clear(o)
        for offset,value in [(0x12c,1),(0x130,8),(0x124,0x12),(0x128,0x12),
                             (0x13c,index),(0x10c,8),(0x17c,2)]:x.word(p+offset,value)
        x.run(0x2f24680,[p,o])
        result=list(struct.unpack("<4h",x.uc.mem_read(o+0x3c,8)))
        assert result==wanted and x.template[0xaf50+index]==gain
        color.append({"display":display,"native":native,"index":index,"gain":gain,
            "output_storage_order_3c_3e_40_42":result,
            "matrix_row_order":[result[0],result[1],result[3],result[2]]})
    md=study.base.Cs(study.base.CS_ARCH_ARM64,study.base.CS_MODE_LITTLE_ENDIAN)
    asm=[]
    for title,block,base,lo,hi in [
        ("Перевод кодов меню",x.a,0x1101000,0x12e67ac,0x12e68ec),
        ("Упаковка сдвига баланса белого",x.b,0x29ae000,0x2e62290,0x2e623cc),
        ("Из основной структуры в промежуточную",x.b,0x29ae000,0x2df1724,0x2df178c),
        ("Из промежуточной структуры в цветовой блок",x.b,0x29ae000,0x2f39e50,0x2f39ee0),
        ("Выбор множителя Цвет",x.b,0x29ae000,0x2f243c8,0x2f243fc),
    ]:
        asm.append("; "+title)
        for va,size,mnemonic,args in md.disasm_lite(block[lo-base:hi-base],lo):asm.append(f"{va:08X} {mnemonic:8} {args}")
        asm.append("")
    (HERE/"Связь_меню_и_параметров.asm").write_text("\n".join(asm),encoding="utf-8")
    proof={"date":"2026-10-31","source_sha256":study.sha(x.raw),"virtual_runs":len(x.runs),
        "WB_conversion_checks":len(wb),"WB_shift_conversion_checks":len(shifts),
        "WB_shift_pack_checks":len(shifts),"WB_modes":wb,"WB_shifts":shifts,
        "tone_examples":cases,"color_examples":color,
        "WB_limit":"Internal codes and develop parameter packing only; RGB gain/pixel path not established",
        "pictures_are_synthetic_illustrations":True,
        "pictures_not_rendered_by_this_firmware":True,
        "input_unchanged":study.sha(study.base.SOURCE.read_bytes())==study.sha(x.raw)}
    assert proof["input_unchanged"]
    (HERE/"Связь_с_меню_проверки.json").write_text(json.dumps(proof,ensure_ascii=False,indent=2)+"\n",encoding="utf-8")
    print(json.dumps({k:proof[k] for k in ["virtual_runs","WB_conversion_checks","WB_shift_conversion_checks","WB_shift_pack_checks","input_unchanged"]},indent=2))

if __name__=="__main__":main()
