# Чтение таблиц перевода значений из распакованного блока I прошивки X-H2 5.30 (b0.bin). MIT.
import struct,re,sys
B0=0x1101000
d=open('b0.bin','rb').read()
names=[m.group().decode() for m in re.finditer(rb'UI_SETP_[A-Z0-9_]+',d)][1:]
ARR=0xad4ab8
def table(pid):
    p=struct.unpack_from('<Q',d,ARR+pid*8)[0]
    if not (B0<=p<B0+len(d)): return None
    o=p-B0; rows=[]
    while len(rows)<80:
        r=struct.unpack_from('<4i',d,o); 
        if r[0]==0xffff or r==(65535,65535,65535,65535): break
        rows.append(r); o+=16
    return rows
if __name__=='__main__':
    for a in sys.argv[1:]:
        pid=int(a,16); print(hex(pid),names[pid],table(pid))
