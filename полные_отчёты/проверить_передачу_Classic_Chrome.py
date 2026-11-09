"""Проверка чтения таблиц и двух следующих записей коэффициентов; камера не используется."""
from pathlib import Path
import sys, importlib.util, struct, json, hashlib

ROOT=Path(__file__).resolve().parent
sys.path.insert(0,str(ROOT/'инструменты'))
from capstone import Cs, CS_ARCH_ARM64, CS_MODE_ARM

src=ROOT/'Рецепты'/'Цветовые_этапы_31.10.2026'/'проверить_цветовые_этапы.py'
spec=importlib.util.spec_from_file_location('color_study_transfer',src)
study=importlib.util.module_from_spec(spec);spec.loader.exec_module(study)
x=study.Study()
cs=Cs(CS_ARCH_ARM64,CS_MODE_ARM)
outdir=ROOT/'Связь_процессора_и_цвета';outdir.mkdir(exist_ok=True)

def dis(start,end):
    return [{'address':f'0x{z.address:08X}','bytes':z.bytes.hex(' ').upper(),
             'mnemonic':z.mnemonic,'operands':z.op_str}
            for z in cs.disasm(x.b[start-0x29ae000:end-0x29ae000],start)]

cases=[]
p,q=0x60000000,0x60010000
for display,index,gain,expected in [(0,4,128,[885,-10,859,-12]),(2,6,141,[974,-12,946,-14])]:
    x.clear(p)
    for off,val in [(0x100,0),(0x12c,1),(0x130,8),(0x124,0x12),
                    (0x128,0x12),(0x13c,index),(0x10c,8),(0x17c,2)]:
        x.word(p+off,val)
    x.clear(q);x.run(0x2f24680,[p,q])
    block=list(struct.unpack('<4h',x.uc.mem_read(q+0x3c,8)))
    assert block==expected
    x.clear(q);x.run(0x2f26fdc,[p,q])
    packet=list(struct.unpack('<4h',x.uc.mem_read(q+2,8)))
    assert packet==[expected[0],expected[2],expected[1],expected[3]]
    assert bytes(x.uc.mem_read(q,1))==b'\x01'
    x.clear(q);x.run(0x2f27054,[p,q])
    record=list(struct.unpack('<4h',x.uc.mem_read(q+0x1da,8)))
    assert record==expected
    assert bytes(x.uc.mem_read(q+0xd,1))==b'\x01'
    cases.append({'display_color':display,'color_index':index,'gain':gain,
        'prepared_block_3c_3e_40_42':block,'packet_2_4_6_8':packet,
        'record_1da_1dc_1de_1e0':record,'record_enabled_at_0d':1})

table_entry=0x3438c80+5*16
keys=list(x.keys(table_entry,4));assert keys==[0xaed8,0xaeda,0xaedc,0xaede]
stored=[]
for off,expected in zip(keys,[885,859,8182,8180]):
    val=struct.unpack_from('<H',x.template,off)[0];assert val==expected
    stored.append({'template_offset':hex(off),'dat_offset':hex(0xc0274+off),
                   'raw_bytes':x.raw[0xc0274+off:0xc0274+off+2].hex(' ').upper(),
                   'decoded_u16':val,'signed13':val-8192 if val&4096 else val})

code={
 'read_coefficient_address':dis(0x2f2435c,0x2f24380),
 'coefficient_math':dis(0x2f24818,0x2f2482c),
 'write_prepared_block':dis(0x2f246f8,0x2f2471c),
 'pack_values':dis(0x2f26fdc,0x2f27028),
 'write_larger_record':dis(0x2f27028,0x2f27054),
 'call_pack_and_transfer':dis(0x2f27054,0x2f27084)}
with study.base.SOURCE.open('rb') as f:current=hashlib.file_digest(f,'sha256').hexdigest()
assert current==study.sha(x.raw)
result={'source_sha256':current,'source_unchanged':True,'virtual_runs':len(x.runs),
    'conditions':'Artificial neutral context, same as earlier color checks; no camera, no full pixel pipeline.',
    'coefficient_address_table':'0x03438C80','selected_entry':hex(table_entry),
    'coefficient_storage':stored,'cases':cases,'code':code,
    'limits':'Writes to output records verified; transfer of these four coefficients to physical image-processing registers is not established.'}
(outdir/'Проверка_передачи_Classic_Chrome.json').write_text(json.dumps(result,ensure_ascii=False,indent=2)+'\n',encoding='utf-8')
lines=[]
for label,rows in code.items():
    lines.append('; '+label)
    lines.extend(z['address']+'  '+z['bytes']+'  '+z['mnemonic']+' '+z['operands'] for z in rows)
(outdir/'Проверенные_команды.asm').write_text('\n'.join(lines)+'\n',encoding='utf-8')
print(json.dumps({'cases':cases,'runs':len(x.runs),'source_unchanged':True,
                  'selected_entry':hex(table_entry),'verified_values':stored},ensure_ascii=True,indent=2))
