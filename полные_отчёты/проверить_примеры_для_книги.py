"""Проверяет реальные байты и простые переходы для объяснения устройства прошивки."""
from pathlib import Path
import importlib.util
import json
import struct

ROOT=Path(__file__).resolve().parent
HERE=ROOT/'Рецепты'/'Цветовые_этапы_31.10.2026'
spec=importlib.util.spec_from_file_location('color_study',HERE/'проверить_цветовые_этапы.py')
study=importlib.util.module_from_spec(spec)
spec.loader.exec_module(study)
x=study.Study()
md=study.base.Cs(study.base.CS_ARCH_ARM64,study.base.CS_MODE_LITTLE_ENDIAN)

def instructions(lo,hi):
    if 0x1101000<=lo<0x1101000+len(x.a): block,base=x.a,0x1101000
    elif 0x29ae000<=lo<0x29ae000+len(x.b): block,base=x.b,0x29ae000
    else: block,base=x.low,0x40000
    return [{'address':f'0x{i.address:08X}','module_offset':hex(i.address-base),
             'bytes':i.bytes.hex(' ').upper(),'mnemonic':i.mnemonic,'operands':i.op_str}
            for i in md.disasm(block[lo-base:hi-base],lo)]

code={name:instructions(lo,hi) for name,lo,hi in [
    ('P_to_T',0x2df1758,0x2df1760),('T_to_C',0x2f39e64,0x2f39e70),
    ('frame_to_P',0x2e57320,0x2e57330),
    ('CC_case',0x2f38c84,0x2f38c8c),('CC_store',0x2f38ce0,0x2f38ce8),
    ('settings_read',0x149ae2c,0x149ae50),('HDR_to_task',0x2e00348,0x2e00358),
    ('hardware_write',0x5de10,0x5de18),('metadata_CC',0x2e51840,0x2e51848),
    ('color_math',0x2f247d0,0x2f247f0),('color_lookup',0x2f243d8,0x2f243f0)]}
p,t,c=0x60000000,0x60010000,0x60020000
for ptr in [p,t,c]: x.clear(ptr,0x8000)
x.word(p+0x39b8,13)
x.run(0x2df1758,until=0x2df1760,registers={20:p,19:t})
assert x.u32(t+0x20)==13
x.run(0x2f39e64,until=0x2f39e70,registers={20:t,19:c})
assert x.u32(c+0x130)==8
transfers={'P':hex(p),'T':hex(t),'C':hex(c),
    'P_plus_39B8':bytes(x.uc.mem_read(p+0x39b8,4)).hex(' ').upper(),
    'T_plus_20':bytes(x.uc.mem_read(t+0x20,4)).hex(' ').upper(),
    'C_plus_130':bytes(x.uc.mem_read(c+0x130,4)).hex(' ').upper()}

coefficients=[]
for key,wanted in [(0xaed8,885),(0xaeda,859),(0xaedc,8182),(0xaede,8180)]:
    off=0xc0274+key
    val=struct.unpack_from('<H',x.template,key)[0]
    assert val==wanted
    signed=(val&0x1fff)-(0x2000 if val&0x1000 else 0)
    coefficients.append({'template_offset':hex(key),'file_offset':hex(off),
        'raw_bytes':x.raw[off:off+2].hex(' ').upper(),
        'inverted_bytes':x.data[off:off+2].hex(' ').upper(),
        'stored_u16':val,'interpreted_s13':signed})
gains=[]
for key,wanted in [(0xaf54,128),(0xaf56,141)]:
    off=0xc0274+key
    assert x.data[off]==wanted
    gains.append({'template_offset':hex(key),'file_offset':hex(off),
        'raw_byte':f'{x.raw[off]:02X}','inverted_byte':f'{x.data[off]:02X}','value':wanted})

result={'source_sha256':study.sha(x.raw),'source_size':len(x.raw),
    'raw_version_bytes':x.raw[0x204:0x20c].hex(' ').upper(),
    'fflz_header_inverted':x.data[0x840274:0x840274+20].hex(' ').upper(),
    'fflz_header_fields':list(struct.unpack_from('<5I',x.data,0x840274)),
    'code':code,'transfers':transfers,'virtual_transfer_runs':len(x.runs),
    'coefficient_storage':coefficients,'gain_storage':gains,
    'template_signature_bytes':x.template[0x202:0x204].hex(' ').upper(),
    'device_tree_bytes':x.data[0x3c40274:0x3c4027c].hex(' ').upper(),
    'elf_bytes':x.data[0x4137274:0x4137274+20].hex(' ').upper(),
    'source_unchanged':study.sha(study.base.SOURCE.read_bytes())==study.sha(x.raw)}
assert result['source_unchanged']
out=ROOT/'Доказательства_для_объяснения_прошивки.json'
out.write_text(json.dumps(result,ensure_ascii=False,indent=2)+'\n',encoding='utf-8')
print(json.dumps(result,ensure_ascii=True,indent=2))
