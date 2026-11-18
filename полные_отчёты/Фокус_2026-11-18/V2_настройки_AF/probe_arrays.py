import sys
sys.path.insert(0, r'<корень проекта>\Анализ_прошивки\Сравнение_версий_2026-11-16')
from fwcommon import *
from collections import defaultdict
ids=[0x8c0,0x6fb,0x618,0x61c,0x620,0x70d,*range(0x710,0x724),0x1e2]
needles={n for i in ids for n in (struct.pack('<H',i),struct.pack('<I',i))}
for idx in range(3):
 b=load('X-H2','old',idx)
 print('\nBLOCK',idx,b,'len',len(b.data))
 # all dense windows by aligned u16 and u32, union
 for step,fmt in [(2,'H'),(4,'I')]:
  vals=[]
  for off in range(0,len(b.data)-step+1,step):
   v=struct.unpack_from('<'+fmt,b.data,off)[0]
   if v in ids: vals.append((off,v))
  clusters=[]
  for off,v in vals:
   if not clusters or off-clusters[-1][-1][0]>64: clusters.append([])
   clusters[-1].append((off,v))
  print('type',fmt,'clusters >=3')
  for c in clusters:
   if len(c)>=3:
    print(hex(b.base+c[0][0]),len(c),[hex(v) for _,v in c])
 # API callers
 for t in [0x2c93fd4,0x12aa788,0x113a668,0x11335ec,0x1135930,0x11335c4,0x2c88e98,0x1141ee0]:
  calls=bl_callers(b,t)
  if calls: print('callers',hex(t),len(calls),[hex(x[0]) for x in calls[:50]])
