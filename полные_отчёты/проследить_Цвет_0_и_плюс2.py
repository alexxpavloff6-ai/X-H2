"""Пошаговая проверка известных участков цепочки «Цвет»; камера и DAT не изменяются."""
from pathlib import Path
import importlib.util
import json
import struct

ROOT=Path(__file__).resolve().parent
HERE=ROOT/'Рецепты'/'Цветовые_этапы_31.10.2026'
spec=importlib.util.spec_from_file_location('color_study',HERE/'проверить_цветовые_этапы.py')
study=importlib.util.module_from_spec(spec);spec.loader.exec_module(study)
x=study.Study()
p,t,c,out=0x60000000,0x60010000,0x60020000,0x60030000
math_trace=[]
def capture(uc,address,size,user):
    if address in [0x2f2481c,0x2f24820,0x2f24824,0x2f24828,0x2f2482c]:
        math_trace.append({'before_instruction':hex(address),
            'x0':uc.reg_read(study.UC_ARM64_REG_X0),'x4':uc.reg_read(study.UC_ARM64_REG_X4),
            'x5':uc.reg_read(study.UC_ARM64_REG_X5),'x6':uc.reg_read(study.UC_ARM64_REG_X6)})
x.uc.hook_add(study.UC_HOOK_CODE,capture)
cases=[]
for display,expected_native,index,gain,expected in [(0,4,4,128,[885,-10,859,-12]),(2,2,6,141,[974,-12,946,-14])]:
    for pointer in [p,t,c]:x.clear(pointer,0x8000)
    x.clear(out)
    # Последнее числовое представление таблицы: единица меню = 10.
    native=x.run(0x12e67ac,[0x6b3,display*10,4,3])&0xffffffff
    assert native==expected_native
    x.word(p+0x39b4,native)
    x.word(p+0x39b8,13)
    x.run(0x2df1724,until=0x2df172c,registers={20:p,19:t})
    assert x.u32(t+0xc)==native
    for off,val in [(0x100,0),(0x12c,1),(0x130,8),(0x124,0x12),(0x128,0x12),(0x10c,8),(0x17c,2)]:
        x.word(c+off,val)
    x.run(0x2f39ecc,until=0x2f39ee0,registers={20:t,19:c})
    assert x.u32(c+0x13c)==index
    x.run(0x2f243c8,[out+0x200,c])
    got_gain=bytes(x.uc.mem_read(out+0x200,1))[0]
    assert got_gain==gain
    x.run(0x2f24284,[c,out+0x300])
    selector=bytes(x.uc.mem_read(out+0x300,1))[0]
    assert selector==6
    math_trace.clear()
    x.run(0x2f24680,[c,out])
    actual=list(struct.unpack('<4h',x.uc.mem_read(out+0x3c,8)))
    assert actual==expected
    assert [z['x0'] for z in math_trace]==[
        gain,885*gain,885*gain*128,885*gain*128*64,(885*gain*128*64)>>20]
    cases.append({'display':display,'native':native,'P_39B4':x.u32(p+0x39b4),
        'P_39B8_mode':x.u32(p+0x39b8),'T_0C':x.u32(t+0xc),'C_13C':x.u32(c+0x13c),
        'C_130_mode':x.u32(c+0x130),'coefficient_set':selector,'gain':gain,
        'P_bytes':bytes(x.uc.mem_read(p+0x39b4,4)).hex(' ').upper(),
        'T_bytes':bytes(x.uc.mem_read(t+0xc,4)).hex(' ').upper(),
        'C_bytes':bytes(x.uc.mem_read(c+0x13c,4)).hex(' ').upper(),
        'output_3C_3E_40_42':actual,
        'output_bytes':bytes(x.uc.mem_read(out+0x3c,8)).hex(' ').upper(),
        'math_trace':list(math_trace)})
result={'source_sha256':study.sha(x.raw),'source_unchanged':study.sha(study.base.SOURCE.read_bytes())==study.sha(x.raw),
        'virtual_runs':len(x.runs),'cases':cases,
        'scope':'Separate unmodified firmware fragments executed with synthetic context; GUI event handler and final pixel calculation not emulated.'}
assert result['source_unchanged']
target=ROOT/'Цвет_0_плюс2_пошаговая_проверка.json'
target.write_text(json.dumps(result,ensure_ascii=False,indent=2)+'\n',encoding='utf-8')
print(json.dumps(result,ensure_ascii=True,indent=2))
