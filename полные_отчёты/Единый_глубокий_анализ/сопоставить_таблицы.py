"""Read homologous firmware tables without inferring runtime reachability."""
from pathlib import Path
import hashlib
import importlib.util
import json
import struct
import sys

HERE = Path(__file__).resolve().parent
ROOT = HERE.parent.parent
sys.path.insert(0, str(HERE.parent / 'инструменты'))
spec = importlib.util.spec_from_file_location('base_tables', HERE.parent / 'анализ_файла.py')
base = importlib.util.module_from_spec(spec)
spec.loader.exec_module(base)
FILES = {
 'X-H2': ('FIRMWARE/ver 5.30/FWUP0028.DAT', 'be47168cb075ef726e67cb4bb08175a896047a3b0de2bcb6e65333b22cfcb203',0x300274,0x840274,0x657bd0,0xa8acd0,0xc0274,0xaf50),
 'X-H2S': ('Firmware на прочиеFuji/FWUP0027.DAT','87c566c1ff6343e4c7463a4ef968183f41d1f24cc63d610433d3a387b13f731b',0x300274,0x840274,0x6573e8,0xa9c4a8,0xc0274,0xaf50),
 'X-T5': ('Firmware на прочиеFuji/FWUP0030.DAT','790d6deecf26766188b0e506e40645e6b816addfeba39a52334349405421724e',0x300274,0x820274,0x658c70,0xa79688,0xc0274,0xaf50),
 'X100VI': ('Firmware на прочиеFuji/FPUPDATE.DAT','0d48d2ae26ac7ebab9b0e4cac56324807ec1ea8ae30df06b0b9e79066dc0a14a',0x9c02bc,0x10e02bc,0x6a2d90,0xad0588,0x6602bc,0xb153),
}

def signed13(x):
 x &= 0x1fff
 return x-0x2000 if x&0x1000 else x

def main():
 result={}
 for model,(rel,sha,ao,bo,table,keypos,template,gainpos) in FILES.items():
  path=ROOT/rel; raw=path.read_bytes(); assert hashlib.sha256(raw).hexdigest()==sha
  data=raw.translate(base.TRANSLATION); a=base.unpack_fflz(data,ao); b=base.unpack_fflz(data,bo)
  rows=[list(struct.unpack_from('<4I',a,table+16*i)) for i in range(26)]
  keys=list(struct.unpack_from('<4I',b,keypos))
  assert all(0<=k<0xc6c00-1 for k in keys)
  values=[struct.unpack_from('<H',data,template+k)[0] for k in keys]
  scales=list(data[template+gainpos:template+gainpos+9])
  assert hashlib.sha256(path.read_bytes()).hexdigest()==sha
  result[model]={'source_sha256':sha,'first_fflz':hex(ao),'second_fflz':hex(bo),'mode_table_offset_decoded':hex(table),'mode_table_address':hex(struct.unpack_from('<Q',a,8)[0]+table),'mode_table_u32':rows,'sixth_key_row_offset_decoded':hex(keypos),'template_dat_offset':hex(template),'key_offsets':[hex(k) for k in keys],'raw_u16':values,'signed_13bit':[signed13(v) for v in values],'nine_bytes_at_candidate_gain_offset':scales,'gain_offset_in_template':hex(gainpos),'source_unchanged':True}
 assert all(r['mode_table_u32'][14]==[15,10,13,11] for r in result.values())
 (HERE/'Таблицы_режимов_и_коэффициентов.json').write_text(json.dumps(result,ensure_ascii=False,indent=2)+'\n',encoding='utf-8')
 ref=result['X-H2']['mode_table_u32']
 print(json.dumps({m:{'row14':r['mode_table_u32'][14],'different_rows_vs_XH2':[i for i,row in enumerate(r['mode_table_u32']) if row!=ref[i]],'sixth_row_signed_13bit':r['signed_13bit'],'nine_gain_bytes':r['nine_bytes_at_candidate_gain_offset']} for m,r in result.items()},ensure_ascii=False,indent=2))

if __name__=='__main__':
 main()
