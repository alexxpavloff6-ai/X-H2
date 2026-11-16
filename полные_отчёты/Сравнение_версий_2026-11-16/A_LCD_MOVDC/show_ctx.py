# -*- coding: utf-8 -*-
"""Печать фрагмента writers_ctx.txt по префиксу заголовка (для консоли)."""
import sys

path = 'writers_ctx.txt'
raw = open(path, 'rb').read()
if raw[:2] in (b'\xff\xfe', b'\xfe\xff'):
    txt = raw.decode('utf-16')
elif raw[:3] == b'\xef\xbb\xbf':
    txt = raw.decode('utf-8-sig')
else:
    txt = raw.decode('utf-8', 'replace')
pref = sys.argv[1] if len(sys.argv) > 1 else ''
for blk in txt.split('====='):
    if blk.lstrip().startswith(pref):
        print('=====' + blk)
