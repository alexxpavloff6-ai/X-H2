"""Find selected UTF-16LE substrings in the XOR-transformed DAT; offsets are DAT offsets."""
from pathlib import Path
import re,csv,hashlib
H=Path(__file__).resolve().parent; p=H.parents[2]/'Firmware на прочиеFuji'/'FWUP0027.DAT'
raw=p.read_bytes(); assert hashlib.sha256(raw).hexdigest()=='87c566c1ff6343e4c7463a4ef968183f41d1f24cc63d610433d3a387b13f731b'
d=raw.translate(bytes.maketrans(bytes(range(256)),bytes(reversed(range(256)))))
words=['SHOOTING MENU','FILM SIMULATION','FACE/EYE DETECTION','АВТОФОКУС','ИМИТАЦИЯ','CLASSIC CHROME','REALA ACE','AF-C CUSTOM']
with (H/'ресурсы_utf16.tsv').open('w',encoding='utf-8',newline='') as f:
 w=csv.writer(f,delimiter='\t',lineterminator='\n'); w.writerow(['DAT_XOR_offset','search','zero_terminated_context'])
 for word in words:
  for m in re.finditer(re.escape(word.encode('utf-16le')),d,re.I):
   off=m.start();end=off
   while end+1<len(d) and d[end:end+2]!=b'\0\0' and end-off<512:end+=2
   text=d[off:end].decode('utf-16le',errors='replace').replace('\t',' ').replace('\n',' ')
   w.writerow([hex(off),word,text])
